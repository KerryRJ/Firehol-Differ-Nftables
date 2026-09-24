use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::collections::HashSet;
use std::net::IpAddr;

pub(crate) struct Ipset {
    pub(crate) ips: HashSet<String>,
}

impl Ipset {
    pub(crate) fn new() -> Self {
        Self {
            ips: HashSet::new(),
        }
    }
    pub(crate) fn from(mut self, lines: &str) -> Self {
        for line in lines.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            self.ips.insert(trimmed.to_string());
        }
        self
    }

    pub(crate) fn consolidate(&mut self) {
        let mut networks = Vec::new();
        let mut other_rows = HashSet::new();

        for row in self.ips.drain() {
            match row.parse::<IpNet>() {
                Ok(network) => networks.push(network),
                Err(_) => match row.parse::<IpAddr>() {
                    Ok(IpAddr::V4(address)) => {
                        networks.push(IpNet::V4(Ipv4Net::new(address, 32).unwrap()));
                    }
                    Ok(IpAddr::V6(address)) => {
                        networks.push(IpNet::V6(Ipv6Net::new(address, 128).unwrap()));
                    }
                    Err(_) => {
                        other_rows.insert(row);
                    }
                },
            }
        }

        self.ips = other_rows;
        self.ips.extend(
            IpNet::aggregate(&networks)
                .into_iter()
                .map(|network| network.to_string()),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::Ipset;

    #[test]
    fn consolidate_includes_bare_ip_addresses() {
        let mut ipset = Ipset::new().from("192.0.2.0/32\n192.0.2.1\n192.0.2.2\n192.0.2.3\nlabel");

        ipset.consolidate();

        assert!(ipset.ips.contains("192.0.2.0/30"));
        assert!(ipset.ips.contains("label"));
        assert_eq!(ipset.ips.len(), 2);
    }
}
