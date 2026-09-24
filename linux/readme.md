# firehol-linux

`firehol-linux` runs the FireHOL list scheduler as a systemd service.

## Requirements

- Ubuntu/Debian on `amd64` with systemd
- `curl` or `wget` to download the package
- Network access to the configured FireHOL list URLs

## Install

Download the latest Ubuntu/Debian package from GitHub Releases with either `curl`
or `wget`, then install it with `apt`:

```sh
curl -fL \
  https://github.com/KerryRJ/Firehol-Differ-Nftables/releases/latest/download/firehol-differ-nftables-linux-amd64.deb \
  -o firehol-differ-nftables-linux-amd64.deb
sudo apt install ./firehol-differ-nftables-linux-amd64.deb
```

Alternatively, using `wget`:

```sh
wget \
  https://github.com/KerryRJ/Firehol-Differ-Nftables/releases/latest/download/firehol-differ-nftables-linux-amd64.deb \
  -O firehol-differ-nftables-linux-amd64.deb
sudo apt install ./firehol-differ-nftables-linux-amd64.deb
```

The package installs the service binary, default `/etc/firehol-differ-nftables/config.toml`, and
systemd unit. It creates a dedicated `firehol-differ-nftables` system account and the
service-writable `/var/lib/firehol-differ-nftables` data folder, then enables and starts
the service. No build or separate setup step is required. Edit the configuration after
installation if needed:

```sh
sudo nano /etc/firehol-differ-nftables/config.toml
sudo systemctl reload firehol-differ-nftables
```

The service runs as `firehol-differ-nftables`, reads its configuration from
`/etc/firehol-differ-nftables/config.toml`, and writes generated data to
`/var/lib/firehol-differ-nftables`.

The latest successfully downloaded lists are reconciled into the nftables sets
when the service starts and after each scheduled fetch. The package also installs
a systemd drop-in that notifies this service after `nftables.service` loads its
rules, so the cached sets are restored after nftables restarts or reloads. The
service needs `CAP_NET_ADMIN` to update its dedicated `inet firehol` table.

The `whitelist` configuration setting populates `firehol_whitelist_ipv4` and
`firehol_whitelist_ipv6`. In your nftables rules, match these sets before
the downloaded list sets so whitelisted traffic is accepted before
blacklist matches. The default whitelist contains `10.0.0.0/8`, `172.16.0.0/12`,
`192.168.0.0/16`, and `fc00::/7`; set `whitelist = []` to leave them empty.

## Check the nftables sets

List all rules and sets in the service's table:

```sh
sudo nft list table inet firehol
```

To inspect one set at a time, including its elements, use:

```sh
sudo nft list set inet firehol FullBogonsIpv4
sudo nft list set inet firehol FullBogonsIpv6
sudo nft list set inet firehol FireholL1
sudo nft list set inet firehol FireholL2
sudo nft list set inet firehol firehol_whitelist_ipv4
sudo nft list set inet firehol firehol_whitelist_ipv6
```

Each downloaded list has its own set: `FullBogonsIpv4`, `FullBogonsIpv6`,
`FireholL1`, and `FireholL2`. The whitelist sets contain the configured
whitelist addresses. The sets are created
and populated by the service, so an empty set can mean the initial fetch has
not completed yet. Check the service logs below if a set is missing or remains
empty.
Check its status and logs with:

```sh
systemctl status firehol-differ-nftables.service
journalctl -u firehol-differ-nftables.service
```

Reload the service after changing its configuration. Reload sends `SIGHUP`; the
service reads the new configuration and applies it to the scheduler without
restarting the systemd service:

```sh
sudo systemctl reload firehol-differ-nftables
```

## Stop or uninstall

```sh
sudo apt remove firehol-differ-nftables
```

Removing the package stops and disables the service. The configuration and data are
preserved.
