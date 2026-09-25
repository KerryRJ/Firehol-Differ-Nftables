use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::collections::HashSet;
use std::net::IpAddr;

pub(crate) struct Ipset {
    pub(crate) ips: HashSet<IpNet>,
    networks: Vec<IpNet>,
}

impl Ipset {
    pub(crate) fn new() -> Self {
        Self {
            ips: HashSet::new(),
            networks: Vec::new(),
        }
    }
    pub(crate) fn from(mut self, lines: &str) -> Self {
        self.networks.extend(parse_networks(lines));
        self
    }

    pub(crate) fn consolidate(&mut self) {
        if self.networks.is_empty() {
            return;
        }
        self.ips.clear();
        self.ips.extend(IpNet::aggregate(&self.networks));
        self.networks.clear();
    }

}

fn parse_network(row: &str) -> Option<IpNet> {
    match row.parse::<IpNet>() {
        Ok(network) => Some(network),
        Err(_) => match row.parse::<IpAddr>() {
            Ok(IpAddr::V4(address)) => Some(IpNet::V4(Ipv4Net::new(address, 32).unwrap())),
            Ok(IpAddr::V6(address)) => Some(IpNet::V6(Ipv6Net::new(address, 128).unwrap())),
            Err(_) => None,
        },
    }
}

fn parse_networks(lines: &str) -> Vec<IpNet> {
    lines.lines().filter_map(|line| {
        let row = line.trim();
        if row.is_empty() || row.starts_with('#') {
            None
        } else {
            parse_network(row)
        }
    }).collect()
}


#[cfg(test)]
mod tests {
    use ipnet::IpNet;
    use super::Ipset;

    #[test]
    fn consolidate_keeps_only_ip_addresses_and_networks() {
        let mut ipset = Ipset::new().from("192.0.2.0/32\n192.0.2.1\n192.0.2.2\n192.0.2.3\nlabel");

        ipset.consolidate();

        assert!(ipset.ips.contains(&"192.0.2.0/30".parse::<IpNet>().unwrap()));
        assert_eq!(ipset.ips.len(), 1);
    }
}
