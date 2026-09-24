use anyhow::{Context, Result, anyhow, ensure};
use nftables::{
    expr::{Expression, NamedExpression, Payload, PayloadField, Prefix},
    schema::{Chain, Element, FlushObject, NfCmd, NfListObject, NfObject, Nftables, Rule, Set, SetFlag, SetType, SetTypeValue, Table},
    stmt::{Drop, Log, Match, Operator, Statement},
    types::{NfChainPolicy, NfChainType, NfFamily, NfHook},
};
use std::{borrow::Cow, collections::HashSet, io::Write, process::{Command, Stdio}};

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

pub(super) fn replace_lists(lists: &[Vec<String>], whitelist: &[String], github_networks: &[String], log_blocked: bool) -> Result<()> {
    ensure!(lists.len() == DOWNLOADED_SETS.len(), "Expected one entry list per downloaded source");
    ensure_table_and_sets()?;
    let mut commands = Vec::new();
    append_whitelist(&mut commands, whitelist, github_networks)?;
    for ((name, _), networks) in DOWNLOADED_SETS.iter().zip(lists) {
        let current = read_set_elements(name)?;
        let desired: HashSet<String> = networks.iter().cloned().collect();
        let additions: Vec<_> = desired.difference(&current).cloned().collect();
        let deletions: Vec<_> = current.difference(&desired).cloned().collect();
        commands.extend(named_element_commands(name, &deletions, false)?);
        commands.extend(named_element_commands(name, &additions, true)?);
    }
    append_prerouting_rules(&mut commands, log_blocked);
    run_document(commands)
}

fn ensure_table_and_sets() -> Result<()> {
    let table_list = Command::new("nft").args(["-j", "list", "table", "inet", TABLE]).output()
        .context("Failed to run nft; install nftables")?;
    if !table_list.status.success() {
        run_document(vec![NfObject::CmdObject(NfCmd::Add(NfListObject::Table(Table {
            family: FAMILY, name: TABLE.into(), handle: None,
        })))])?;
    }
    let sets_list = Command::new("nft").args(["-j", "list", "table", "inet", TABLE]).output()?;
    let listed: serde_json::Value = serde_json::from_slice(&sets_list.stdout).context("Could not parse nft table listing")?;
    let existing: HashSet<String> = listed["nftables"].as_array().into_iter().flatten()
        .filter_map(|entry| entry.get("set").and_then(|set| set.get("name")).and_then(serde_json::Value::as_str).map(str::to_owned))
        .collect();
    let mut missing = Vec::new();
    for (name, set_type) in DOWNLOADED_SETS {
        if !existing.contains(name) { missing.push(set_command(name, set_type)); }
    }
    if !existing.contains(WHITELIST_IPV4_SET) { missing.push(set_command(WHITELIST_IPV4_SET, SetType::Ipv4Addr)); }
    if !existing.contains(WHITELIST_IPV6_SET) { missing.push(set_command(WHITELIST_IPV6_SET, SetType::Ipv6Addr)); }
    if !existing.contains(GITHUB_WHITELIST_IPV4_SET) { missing.push(set_command(GITHUB_WHITELIST_IPV4_SET, SetType::Ipv4Addr)); }
    if !existing.contains(GITHUB_WHITELIST_IPV6_SET) { missing.push(set_command(GITHUB_WHITELIST_IPV6_SET, SetType::Ipv6Addr)); }
    let chains: HashSet<String> = listed["nftables"].as_array().into_iter().flatten()
        .filter_map(|entry| entry.get("chain").and_then(|chain| chain.get("name")).and_then(serde_json::Value::as_str).map(str::to_owned))
        .collect();
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
    let json = serde_json::to_vec(&document)?;
    let mut child = Command::new("nft").args(["-j", "-f", "-"])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().context("Failed to start nft; install nftables and grant the service CAP_NET_ADMIN")?;
    child.stdin.take().context("Failed to open nft stdin")?.write_all(&json)?;
    let output = child.wait_with_output()?;
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

fn append_whitelist(commands: &mut Vec<NfObject<'static>>, networks: &[String], github_networks: &[String]) -> Result<()> {
    // Reconcile the small user-configured set on each update. The whitelist is
    // independent from the downloaded blacklist network sets.
    let configured: Vec<&str> = networks.iter().map(String::as_str).collect();
    append_whitelist_set(commands, WHITELIST_IPV4_SET, &configured, true)?;
    append_whitelist_set(commands, WHITELIST_IPV6_SET, &configured, false)?;
    let github: Vec<&str> = github_networks.iter().map(String::as_str).collect();
    append_whitelist_set(commands, GITHUB_WHITELIST_IPV4_SET, &github, true)?;
    append_whitelist_set(commands, GITHUB_WHITELIST_IPV6_SET, &github, false)?;
    Ok(())
}

fn append_whitelist_set(commands: &mut Vec<NfObject<'static>>, name: &str, networks: &[&str], ipv4: bool) -> Result<()> {
    let parsed: Vec<ipnet::IpNet> = networks.iter().map(|value| {
        value.parse::<ipnet::IpNet>()
            .map(|net| net.trunc())
            .with_context(|| format!("Invalid whitelist network: {value}"))
    }).collect::<Result<_>>()?;
    let desired: HashSet<String> = parsed.iter()
        .filter(|candidate| candidate.addr().is_ipv4() == ipv4)
        .filter(|candidate| !parsed.iter().any(|outer| {
            outer.prefix_len() < candidate.prefix_len() && outer.contains(*candidate)
        }))
        .map(ToString::to_string)
        .collect();
    let current = read_set_elements(name)?;
    let additions: Vec<_> = desired.difference(&current).cloned().collect();
    let deletions: Vec<_> = current.difference(&desired).cloned().collect();
    commands.extend(named_element_commands(name, &deletions, false)?);
    commands.extend(named_element_commands(name, &additions, true)?);
    Ok(())
}

fn read_set_elements(name: &str) -> Result<HashSet<String>> {
    let output = Command::new("nft").args(["-j", "list", "set", "inet", TABLE, name]).output()
        .with_context(|| format!("Failed to list nftables set {name}"))?;
    if !output.status.success() {
        return Err(anyhow!("Failed to list nftables set {name}: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    let listed: serde_json::Value = serde_json::from_slice(&output.stdout).context("Could not parse nft set listing")?;
    Ok(listed["nftables"].as_array().into_iter().flatten()
        .filter_map(|entry| entry.get("set").and_then(|set| set.get("elem")).and_then(serde_json::Value::as_array))
        .flatten().filter_map(|element| {
            if let Some(prefix) = element.get("prefix") {
                Some(format!("{}/{}", prefix.get("addr")?.as_str()?, prefix.get("len")?.as_u64()?))
            } else { element.as_str().map(str::to_owned) }
        }).collect())
}

fn named_element_commands(name: &str, networks: &[String], add: bool) -> Result<Vec<NfObject<'static>>> {
    let mut commands = Vec::new();
    for value in networks {
        let network: ipnet::IpNet = value.parse().with_context(|| format!("Invalid network: {value}"))?;
        let (addr, len) = match network {
            ipnet::IpNet::V4(net) => (net.network().to_string(), net.prefix_len()),
            ipnet::IpNet::V6(net) => (net.network().to_string(), net.prefix_len()),
        };
        let element = Element { family: FAMILY, table: TABLE.into(), name: Cow::Owned(name.to_owned()), elem: vec![Expression::Named(NamedExpression::Prefix(Prefix { addr: Box::new(Expression::String(Cow::Owned(addr))), len: len.into() }))].into() };
        commands.push(NfObject::CmdObject(if add { NfCmd::Add(NfListObject::Element(element)) } else { NfCmd::Delete(NfListObject::Element(element)) }));
    }
    Ok(commands)
}
