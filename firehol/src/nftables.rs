use anyhow::{Context, Result, anyhow, ensure};
use log::info;
use nftables::{
    expr::{Expression, NamedExpression, Payload, PayloadField, Prefix},
    schema::{Chain, Element, FlushObject, NfCmd, NfListObject, NfObject, Nftables, Rule, Set, SetFlag, SetType, SetTypeValue, Table},
    stmt::{Drop, Log, Match, Operator, Statement},
    types::{NfChainPolicy, NfChainType, NfFamily, NfHook},
};
use serde::Deserialize;
use std::{borrow::Cow, collections::HashSet, io::BufReader, net::IpAddr, process::{Command, Stdio}};

#[derive(Deserialize)]
struct TableListing {
    nftables: Vec<TableListingEntry>,
}

enum TableListingEntry {
    Set(String),
    Chain(String),
    Other,
}

#[derive(Deserialize)]
struct ListedNamedObject {
    name: String,
}

impl<'de> Deserialize<'de> for TableListingEntry {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct EntryVisitor;

        impl<'de> serde::de::Visitor<'de> for EntryVisitor {
            type Value = TableListingEntry;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an nftables listing entry")
            }

            fn visit_map<M>(self, mut map: M) -> std::result::Result<Self::Value, M::Error>
            where
                M: serde::de::MapAccess<'de>,
            {
                let mut entry = TableListingEntry::Other;
                while let Some(kind) = map.next_key::<String>()? {
                    entry = match kind.as_str() {
                        "set" => TableListingEntry::Set(map.next_value::<ListedNamedObject>()?.name),
                        "chain" => TableListingEntry::Chain(map.next_value::<ListedNamedObject>()?.name),
                        _ => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                            TableListingEntry::Other
                        }
                    };
                }
                Ok(entry)
            }
        }

        deserializer.deserialize_map(EntryVisitor)
    }
}

#[derive(Deserialize)]
struct SetListing<'a> {
    #[serde(borrow)]
    nftables: Vec<SetListingEntry<'a>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase", bound(deserialize = "'de: 'a"))]
enum SetListingEntry<'a> {
    Metainfo(serde::de::IgnoredAny),
    Set(ListedElements<'a>),
    #[serde(other)]
    Other,
}

#[derive(Deserialize)]
struct ListedElements<'a> {
    #[serde(borrow)]
    elem: Option<Vec<ListedElement<'a>>>,
}

enum ListedElement<'a> {
    Prefix(ListedPrefix<'a>),
    Address(Cow<'a, str>),
    Other,
}

impl<'de, 'a> Deserialize<'de> for ListedElement<'a>
where
    'de: 'a,
{
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ElementVisitor<'a>(std::marker::PhantomData<&'a ()>);

        impl<'de, 'a> serde::de::Visitor<'de> for ElementVisitor<'a>
        where
            'de: 'a,
        {
            type Value = ListedElement<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an nftables set element")
            }

            fn visit_borrowed_str<E>(self, value: &'de str) -> std::result::Result<Self::Value, E> {
                Ok(ListedElement::Address(Cow::Borrowed(value)))
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(ListedElement::Address(Cow::Owned(value.to_owned())))
            }

            fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
                Ok(ListedElement::Address(Cow::Owned(value)))
            }

            fn visit_map<M>(self, mut map: M) -> std::result::Result<Self::Value, M::Error>
            where
                M: serde::de::MapAccess<'de>,
            {
                let mut element = ListedElement::Other;
                while let Some(kind) = map.next_key::<String>()? {
                    if kind == "prefix" {
                        element = ListedElement::Prefix(map.next_value::<ListedPrefix<'a>>()?);
                    } else {
                        map.next_value::<serde::de::IgnoredAny>()?;
                    }
                }
                Ok(element)
            }

            fn visit_seq<S>(self, mut sequence: S) -> std::result::Result<Self::Value, S::Error>
            where
                S: serde::de::SeqAccess<'de>,
            {
                while sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {}
                Ok(ListedElement::Other)
            }

            fn visit_bool<E>(self, _: bool) -> std::result::Result<Self::Value, E> {
                Ok(ListedElement::Other)
            }

            fn visit_i64<E>(self, _: i64) -> std::result::Result<Self::Value, E> {
                Ok(ListedElement::Other)
            }

            fn visit_u64<E>(self, _: u64) -> std::result::Result<Self::Value, E> {
                Ok(ListedElement::Other)
            }

            fn visit_f64<E>(self, _: f64) -> std::result::Result<Self::Value, E> {
                Ok(ListedElement::Other)
            }

            fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
                Ok(ListedElement::Other)
            }
        }

        deserializer.deserialize_any(ElementVisitor(std::marker::PhantomData))
    }
}

#[derive(Deserialize)]
struct ListedPrefix<'a> {
    #[serde(borrow)]
    addr: Cow<'a, str>,
    len: u8,
}

const FAMILY: NfFamily = NfFamily::INet;
const TABLE: &str = "iodrive";
const PREROUTING_CHAIN: &str = "firehol_prerouting";
const DOWNLOADED_SETS: [(&str, SetType); 4] = [
    ("FireholL1", SetType::Ipv4Addr),
    ("FireholL2", SetType::Ipv4Addr),
    ("FullBogonsIpv4", SetType::Ipv4Addr),
    ("FullBogonsIpv6", SetType::Ipv6Addr),
];
const WHITELIST_IPV4_SET: &str = "WhitelistIPv4";
const WHITELIST_IPV6_SET: &str = "WhitelistIPv6";

const GITHUB_WHITELIST_IPV4_SET: &str = "GithubWhitelistIPv4";
const GITHUB_WHITELIST_IPV6_SET: &str = "GithubWhitelistIPv6";

pub(super) fn replace_lists(
    lists: &[Option<Vec<ipnet::IpNet>>],
    whitelist_ipv4: Option<&[String]>,
    whitelist_ipv6: Option<&[String]>,
    github_networks: Option<&[ipnet::IpNet]>,
    log_blocked: bool,
) -> Result<()> {
    ensure!(lists.len() == DOWNLOADED_SETS.len(), "Expected one entry list per downloaded source");
    ensure_table_and_sets()?;
    let mut commands = Vec::new();
    append_whitelist(&mut commands, whitelist_ipv4, whitelist_ipv6, github_networks)?;
    for ((name, _), networks) in DOWNLOADED_SETS.iter().zip(lists) {
        let Some(networks) = networks else { continue; };
        let current = read_set_elements(name)?;
        let desired: HashSet<ipnet::IpNet> = networks.iter()
            .map(|network| network.trunc())
            .collect();
        let additions = desired.difference(&current).count();
        let deletions = current.difference(&desired).count();
        let after_count = current.len() + additions - deletions;
        info!("nftables set {name}: before={} additions={additions} deletions={deletions} after={after_count}", current.len());
        let deletions: Vec<ipnet::IpNet> = current.difference(&desired).copied().collect();
        let additions: Vec<ipnet::IpNet> = desired.difference(&current).copied().collect();
        if let Some(command) = named_element_command(name, &deletions, false) {
            commands.push(command);
        }
        if let Some(command) = named_element_command(name, &additions, true) {
            commands.push(command);
        }
    }
    append_prerouting_rules(&mut commands, log_blocked);
    run_document(commands)
}

fn ensure_table_and_sets() -> Result<()> {
    let mut table_list = Command::new("nft").args(["-j", "list", "table", "inet", TABLE])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("Failed to run nft; install nftables")?;
    let stdout = table_list.stdout.take().context("Failed to read nft table listing")?;
    let mut stdout = BufReader::new(stdout);
    let listed_result = {
        let mut deserializer = serde_json::Deserializer::from_reader(&mut stdout);
        TableListing::deserialize(&mut deserializer)
            .and_then(|listed| deserializer.end().map(|()| listed))
    };
    if listed_result.is_err() {
        // Drain the pipe if deserialization stopped early, so the nft process
        // cannot block while we wait for it to exit.
        std::io::copy(&mut stdout, &mut std::io::sink())
            .context("Failed to drain nft table listing")?;
    }
    let table_list_status = table_list.wait().context("Failed to wait for nft table listing")?;
    let (existing, chains) = if table_list_status.success() {
        let listed: TableListing = listed_result.context("Could not parse nft table listing")?;
        let mut existing = HashSet::new();
        let mut chains = HashSet::new();
        for entry in listed.nftables {
            match entry {
                TableListingEntry::Set(name) => { existing.insert(name); }
                TableListingEntry::Chain(name) => { chains.insert(name); }
                TableListingEntry::Other => {}
            }
        }
        (existing, chains)
    } else {
        run_document(vec![NfObject::CmdObject(NfCmd::Add(NfListObject::Table(Table {
            family: FAMILY, name: TABLE.into(), handle: None,
        })))])?;
        (HashSet::new(), HashSet::new())
    };
    let mut missing = Vec::new();
    for (name, set_type) in DOWNLOADED_SETS {
        if !existing.contains(name) { missing.push(set_command(name, set_type)); }
    }
    if !existing.contains(WHITELIST_IPV4_SET) { missing.push(set_command(WHITELIST_IPV4_SET, SetType::Ipv4Addr)); }
    if !existing.contains(WHITELIST_IPV6_SET) { missing.push(set_command(WHITELIST_IPV6_SET, SetType::Ipv6Addr)); }
    if !existing.contains(GITHUB_WHITELIST_IPV4_SET) { missing.push(set_command(GITHUB_WHITELIST_IPV4_SET, SetType::Ipv4Addr)); }
    if !existing.contains(GITHUB_WHITELIST_IPV6_SET) { missing.push(set_command(GITHUB_WHITELIST_IPV6_SET, SetType::Ipv6Addr)); }
    if !chains.contains(PREROUTING_CHAIN) {
        missing.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(Chain {
            family: FAMILY,
            table: TABLE.into(),
            name: PREROUTING_CHAIN.into(),
            newname: None,
            handle: None,
            _type: Some(NfChainType::Filter),
            hook: Some(NfHook::Prerouting),
            prio: Some(-500),
            dev: None,
            policy: Some(NfChainPolicy::Accept),
        }))));
    }
    if !missing.is_empty() { run_document(missing)?; }
    Ok(())
}

fn append_prerouting_rules(commands: &mut Vec<NfObject<'static>>, log_blocked: bool) {
    commands.push(NfObject::CmdObject(NfCmd::Flush(FlushObject::Chain(Chain {
        family: FAMILY,
        table: TABLE.into(),
        name: PREROUTING_CHAIN.into(),
        ..Chain::default()
    }))));

    for set in [WHITELIST_IPV4_SET, GITHUB_WHITELIST_IPV4_SET] {
        commands.push(rule_object("ip", set, vec![Statement::Accept(None)]));
    }
    for set in ["FullBogonsIpv4", "FireholL1", "FireholL2"] {
        commands.push(drop_rule("ip", set, log_blocked));
    }
    for set in [WHITELIST_IPV6_SET, GITHUB_WHITELIST_IPV6_SET] {
        commands.push(rule_object("ip6", set, vec![Statement::Accept(None)]));
    }
    commands.push(drop_rule("ip6", "FullBogonsIpv6", log_blocked));
}

fn drop_rule(protocol: &str, set: &str, log_blocked: bool) -> NfObject<'static> {
    let mut statements = Vec::new();
    if log_blocked {
        statements.push(Statement::Log(Some(Log {
            prefix: Some(Cow::Owned(format!("Blocked Iodrive-{set}: "))),
            group: None,
            snaplen: None,
            queue_threshold: None,
            level: None,
            flags: None,
        })));
    }
    statements.push(Statement::Drop(Some(Drop {})));
    rule_object(protocol, set, statements)
}

fn rule_object(protocol: &str, set: &str, statements: Vec<Statement<'static>>) -> NfObject<'static> {
    NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(Rule {
        family: FAMILY,
        table: TABLE.into(),
        chain: PREROUTING_CHAIN.into(),
        expr: vec![
            Statement::Match(Match {
                left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField {
                    protocol: Cow::Owned(protocol.to_owned()),
                    field: "saddr".into(),
                }))),
                right: Expression::String(Cow::Owned(format!("@{set}"))),
                op: Operator::IN,
            }),
        ].into_iter().chain(statements).collect::<Vec<_>>().into(),
        handle: None,
        index: None,
        comment: None,
    })))
}


fn run_document(commands: Vec<NfObject<'static>>) -> Result<()> {
    let document = Nftables { objects: commands.into() };
    let mut child = Command::new("nft").args(["-j", "-f", "-"])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().context("Failed to start nft; install nftables and grant the service CAP_NET_ADMIN")?;
    let mut stdin = child.stdin.take().context("Failed to open nft stdin")?;
    let write_result = serde_json::to_writer(&mut stdin, &document);
    drop(stdin);
    let output = child.wait_with_output()?;
    write_result.context("Failed to stream nftables update")?;
    if !output.status.success() {
        return Err(anyhow!("nft rejected FireHOL update: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    Ok(())
}

fn set_command(name: &str, set_type: SetType) -> NfObject<'static> {
    let mut flags = HashSet::new();
    flags.insert(SetFlag::Interval);
    NfObject::CmdObject(NfCmd::Add(NfListObject::Set(Box::new(Set {
        family: FAMILY,
        table: TABLE.into(),
        name: Cow::Owned(name.to_owned()),
        handle: None,
        set_type: SetTypeValue::Single(set_type),
        policy: None,
        flags: Some(flags),
        elem: None,
        timeout: None,
        gc_interval: None,
        size: None,
        comment: None,
    }))))
}

fn append_whitelist(
    commands: &mut Vec<NfObject<'static>>,
    ipv4_networks: Option<&[String]>,
    ipv6_networks: Option<&[String]>,
    github_networks: Option<&[ipnet::IpNet]>,
) -> Result<()> {
    // Reconcile the small user-configured set on each update. The whitelist is
    // independent from the downloaded blacklist network sets.
    if let Some(ipv4_networks) = ipv4_networks {
        let configured_ipv4: Vec<&str> = ipv4_networks.iter().map(String::as_str).collect();
        append_whitelist_set(commands, WHITELIST_IPV4_SET, &configured_ipv4, true)?;
    }
    if let Some(ipv6_networks) = ipv6_networks {
        let configured_ipv6: Vec<&str> = ipv6_networks.iter().map(String::as_str).collect();
        append_whitelist_set(commands, WHITELIST_IPV6_SET, &configured_ipv6, false)?;
    }
    if let Some(github_networks) = github_networks {
        append_whitelist_networks(commands, GITHUB_WHITELIST_IPV4_SET, github_networks, true)?;
        append_whitelist_networks(commands, GITHUB_WHITELIST_IPV6_SET, github_networks, false)?;
    }
    Ok(())
}

fn append_whitelist_set(commands: &mut Vec<NfObject<'static>>, name: &str, networks: &[&str], ipv4: bool) -> Result<()> {
    let parsed: Vec<ipnet::IpNet> = networks.iter().map(|value| {
        parse_network(value)
            .map(|net| net.trunc())
            .with_context(|| format!("Invalid whitelist network: {value}"))
    }).collect::<Result<_>>()?;
    append_whitelist_networks(commands, name, &parsed, ipv4)
}

fn append_whitelist_networks(commands: &mut Vec<NfObject<'static>>, name: &str, networks: &[ipnet::IpNet], ipv4: bool) -> Result<()> {
    let mut family_networks: Vec<_> = networks.iter()
        .map(|network| network.trunc())
        .filter(|network| network.addr().is_ipv4() == ipv4)
        .collect();
    family_networks.sort_by(|left, right| {
        left.addr().cmp(&right.addr()).then_with(|| left.prefix_len().cmp(&right.prefix_len()))
    });
    let mut desired = Vec::<ipnet::IpNet>::with_capacity(family_networks.len());
    for candidate in family_networks {
        if !desired.iter().any(|outer| {
            outer.prefix_len() < candidate.prefix_len() && outer.contains(&candidate)
        }) {
            desired.push(candidate);
        }
    }
    let desired: HashSet<ipnet::IpNet> = desired.into_iter().collect();
    info!("nftables whitelist set {name}: replacing with {} networks", desired.len());
    commands.push(NfObject::CmdObject(NfCmd::Flush(FlushObject::Set(Box::new(Set {
        family: FAMILY,
        table: TABLE.into(),
        name: Cow::Owned(name.to_owned()),
        handle: None,
        set_type: SetTypeValue::Single(if ipv4 { SetType::Ipv4Addr } else { SetType::Ipv6Addr }),
        policy: None,
        flags: None,
        elem: None,
        timeout: None,
        gc_interval: None,
        size: None,
        comment: None,
    })))));
    let desired: Vec<_> = desired.into_iter().collect();
    if let Some(command) = named_element_command(name, &desired, true) {
        commands.push(command);
    }
    Ok(())
}

fn read_set_elements(name: &str) -> Result<HashSet<ipnet::IpNet>> {
    let output = Command::new("nft").args(["-j", "list", "set", "inet", TABLE, name]).output()
        .with_context(|| format!("Failed to list nftables set {name}"))?;
    if !output.status.success() {
        return Err(anyhow!("Failed to list nftables set {name}: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    let listed: SetListing<'_> = serde_json::from_slice(&output.stdout)
        .context("Could not parse nft set listing")?;
    let mut networks = HashSet::new();
    for element in listed.nftables.into_iter().filter_map(|entry| match entry {
        SetListingEntry::Set(set) => set.elem,
        SetListingEntry::Metainfo(_) => None,
        SetListingEntry::Other => None,
    }).flatten() {
        let network = match element {
            ListedElement::Prefix(prefix) => parse_prefix(&prefix.addr, prefix.len)
                .with_context(|| format!("Invalid network in nftables set {name}: {}/{}", prefix.addr, prefix.len))?,
            ListedElement::Address(address) => parse_network(&address)
                .with_context(|| format!("Invalid network in nftables set {name}: {address}"))?,
            ListedElement::Other => continue,
        };
        networks.insert(network.trunc());
    }
    Ok(networks)
}

fn named_element_command(name: &str, networks: &[ipnet::IpNet], add: bool) -> Option<NfObject<'static>> {
    if networks.is_empty() {
        return None;
    }
    let mut elements = Vec::with_capacity(networks.len());
    for network in networks {
        let (addr, len) = match network {
            ipnet::IpNet::V4(net) => (net.network().to_string(), net.prefix_len()),
            ipnet::IpNet::V6(net) => (net.network().to_string(), net.prefix_len()),
        };
        elements.push(Expression::Named(NamedExpression::Prefix(Prefix {
            addr: Box::new(Expression::String(Cow::Owned(addr))),
            len: len.into(),
        })));
    }
    let element = Element {
        family: FAMILY,
        table: TABLE.into(),
        name: Cow::Owned(name.to_owned()),
        elem: elements.into(),
    };
    Some(NfObject::CmdObject(if add {
        NfCmd::Add(NfListObject::Element(element))
    } else {
        NfCmd::Delete(NfListObject::Element(element))
    }))
}

fn parse_prefix(address: &str, prefix_len: u8) -> Result<ipnet::IpNet> {
    match address.parse::<IpAddr>()? {
        IpAddr::V4(address) => Ok(ipnet::IpNet::V4(ipnet::Ipv4Net::new(address, prefix_len)?)),
        IpAddr::V6(address) => Ok(ipnet::IpNet::V6(ipnet::Ipv6Net::new(address, prefix_len)?)),
    }
}

fn parse_network(value: &str) -> Result<ipnet::IpNet> {
    if let Ok(network) = value.parse::<ipnet::IpNet>() {
        return Ok(network);
    }
    match value.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => Ok(ipnet::IpNet::V4(ipnet::Ipv4Net::new(address, 32)?)),
        Ok(IpAddr::V6(address)) => Ok(ipnet::IpNet::V6(ipnet::Ipv6Net::new(address, 128)?)),
        Err(_) => value.parse::<ipnet::IpNet>().map_err(Into::into),
    }
}
