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
