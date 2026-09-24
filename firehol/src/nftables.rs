use anyhow::{Context, Result, anyhow};
use nftables::{
    expr::{Expression, NamedExpression, Prefix},
    schema::{Element, NfCmd, NfListObject, NfObject, Nftables, Set, SetFlag, SetType, SetTypeValue, Table},
    types::NfFamily,
};
use std::{borrow::Cow, collections::HashSet, io::Write, process::{Command, Stdio}};

const FAMILY: NfFamily = NfFamily::INet;
const TABLE: &str = "firehol";
const IPV4_SET: &str = "firehol_ipv4";
const IPV6_SET: &str = "firehol_ipv6";
const WHITELIST_IPV4_SET: &str = "firehol_whitelist_ipv4";
const WHITELIST_IPV6_SET: &str = "firehol_whitelist_ipv6";

pub(super) fn apply(additions: &[String], deletions: &[String], whitelist: &[String]) -> Result<()> {
    ensure_table_and_sets()?;
    let mut commands = Vec::new();
    append_whitelist(&mut commands, whitelist)?;
    append_elements(&mut commands, deletions, false)?;
    append_elements(&mut commands, additions, true)?;

    run_document(commands)
}

pub(super) fn replace_elements(networks: &[String], whitelist: &[String]) -> Result<()> {
    ensure_table_and_sets()?;
    let mut commands = Vec::new();
    append_whitelist(&mut commands, whitelist)?;
    let (v4, v6) = list_elements()?;
    let desired: HashSet<String> = networks.iter().cloned().collect();
    let additions: Vec<_> = desired.difference(&v4.union(&v6).cloned().collect()).cloned().collect();
    let deletions: Vec<_> = v4.union(&v6).filter(|network| !desired.contains(*network)).cloned().collect();
    commands.extend(element_commands(&deletions, false)?);
    commands.extend(element_commands(&additions, true)?);
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
    if !existing.contains(IPV4_SET) { missing.push(set_command(IPV4_SET, SetType::Ipv4Addr)); }
    if !existing.contains(IPV6_SET) { missing.push(set_command(IPV6_SET, SetType::Ipv6Addr)); }
    if !existing.contains(WHITELIST_IPV4_SET) { missing.push(set_command(WHITELIST_IPV4_SET, SetType::Ipv4Addr)); }
    if !existing.contains(WHITELIST_IPV6_SET) { missing.push(set_command(WHITELIST_IPV6_SET, SetType::Ipv6Addr)); }
    if !missing.is_empty() { run_document(missing)?; }
    Ok(())
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

fn list_elements() -> Result<(HashSet<String>, HashSet<String>)> {
    fn read_set(name: &str) -> Result<HashSet<String>> {
        let output = Command::new("nft").args(["-j", "list", "set", "inet", TABLE, name]).output()
            .with_context(|| format!("Failed to list nftables set {name}"))?;
        if !output.status.success() {
            return Err(anyhow!("Failed to list nftables set {name}: {}", String::from_utf8_lossy(&output.stderr).trim()));
        }
        let listed: serde_json::Value = serde_json::from_slice(&output.stdout).context("Could not parse nft set listing")?;
        let values = listed["nftables"].as_array().into_iter().flatten()
            .filter_map(|entry| entry.get("set").and_then(|set| set.get("elem")).and_then(serde_json::Value::as_array))
            .flatten().filter_map(|element| {
                if let Some(prefix) = element.get("prefix") {
                    Some(format!("{}/{}", prefix.get("addr")?.as_str()?, prefix.get("len")?.as_u64()?))
                } else {
                    element.as_str().map(str::to_owned)
                }
            }).collect();
        Ok(values)
    }
    Ok((read_set(IPV4_SET)?, read_set(IPV6_SET)?))
}

fn append_elements(commands: &mut Vec<NfObject<'static>>, networks: &[String], add: bool) -> Result<()> {
    commands.extend(element_commands(networks, add)?);
    Ok(())
}

fn append_whitelist(commands: &mut Vec<NfObject<'static>>, networks: &[String]) -> Result<()> {
    // Reconcile the small user-configured set on each update. The whitelist is
    // independent from the downloaded blacklist network sets.
    for name in [WHITELIST_IPV4_SET, WHITELIST_IPV6_SET] {
        let current = read_set_elements(name)?;
        let desired: HashSet<String> = networks.iter().map(|value| {
            value.parse::<ipnet::IpNet>()
                .map(|net| net.trunc().to_string())
                .with_context(|| format!("Invalid whitelist network: {value}"))
        }).collect::<Result<_>>()?;
        let desired: HashSet<String> = desired.into_iter().filter(|n| {
            n.parse::<ipnet::IpNet>().is_ok_and(|parsed| if name == WHITELIST_IPV4_SET { parsed.addr().is_ipv4() } else { parsed.addr().is_ipv6() })
        }).collect();
        let additions: Vec<_> = desired.difference(&current).cloned().collect();
        let deletions: Vec<_> = current.difference(&desired).cloned().collect();
        commands.extend(named_element_commands(name, &deletions, false)?);
        commands.extend(named_element_commands(name, &additions, true)?);
    }
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

fn element_commands(networks: &[String], add: bool) -> Result<Vec<NfObject<'static>>> {
    let mut commands = Vec::new();
    for value in networks {
        let network: ipnet::IpNet = value.parse().with_context(|| format!("Invalid network in delta: {value}"))?;
        let (name, addr, len) = match network {
            ipnet::IpNet::V4(net) => (IPV4_SET, net.network().to_string(), net.prefix_len()),
            ipnet::IpNet::V6(net) => (IPV6_SET, net.network().to_string(), net.prefix_len()),
        };
        let element = Element {
            family: FAMILY,
            table: TABLE.into(),
            name: name.into(),
            elem: vec![Expression::Named(NamedExpression::Prefix(Prefix { addr: Box::new(Expression::String(Cow::Owned(addr))), len: len.into() }))].into(),
        };
        let command = if add { NfCmd::Add(NfListObject::Element(element)) } else { NfCmd::Delete(NfListObject::Element(element)) };
        commands.push(NfObject::CmdObject(command));
    }
    Ok(commands)
}
