# windows

`firehol-differ-nftables` runs the FireHOL list scheduler as a Windows service.

## Requirements

- Windows
- Administrator access for service installation
- Rust toolchain and the MSVC build tools, if building from source
- Network access to the configured FireHOL list URLs

## Build

Build on Windows from the repository root:

```powershell
cargo build --release -p windows
```

The executable is created at `target\\release\\firehol-differ-nftables.exe`.

## Create a WiX installer

Install WiX Toolset v7 and its UI extension, then build the release binary and MSI
from the repository root:

```powershell
cargo build --release -p windows
wix extension add WixToolset.UI.wixext/7.0.0
wix build windows\\wix\\main.wxs `
  -ext WixToolset.UI.wixext `
  -arch x64 `
  -d CargoTargetBinDir="$((Resolve-Path .\\target\\release).Path)" `
  -d Version="$(Select-String -Path Cargo.toml -Pattern '^version = \"([^\"]+)\"').Matches.Groups[1].Value" `
  -o .\\target\\release\\firehol-differ-nftables-setup.msi
```

Run the generated MSI as administrator. It installs and starts the
`firehol-differ-nftables` service, installs `config.toml` beside the executable, and
creates the writable data directory at `C:\\ProgramData\\firehol-differ-nftables`.

## Install

Choose an installation directory and copy the executable there. The following example
uses `C:\\Program Files\\firehol-differ-nftables`:

```powershell
$InstallDir = 'C:\\Program Files\\firehol-differ-nftables'
New-Item -ItemType Directory -Force $InstallDir | Out-Null
Copy-Item .\\target\\release\\firehol-differ-nftables.exe $InstallDir
```

The service loads `config.toml` from the same directory as its executable:

```powershell
Copy-Item .\\config.toml $InstallDir\\config.toml
```

The TOML file must include these settings:

```toml
interval = "1h"
path = "."
l1_url = "https://iplists.firehol.org/files/firehol_level1.netset"
l2_url = "https://iplists.firehol.org/files/firehol_level2.netset"
```

Edit `$InstallDir\\config.toml` before starting the service if needed. The `path` setting controls where generated data is written. Its default value of `.` stores
the ETags, downloaded netsets, and delta files in
`C:\\ProgramData\\firehol-differ-nftables`. A different relative path is resolved
from that data directory.

Create and start the service from an elevated PowerShell prompt:

```powershell
$Binary = 'C:\\Program Files\\firehol-differ-nftables\\firehol-differ-nftables.exe'
sc.exe create firehol-differ-nftables binPath= '"C:\\Program Files\\firehol-differ-nftables\\firehol-differ-nftables.exe"' start= auto
sc.exe description firehol-differ-nftables 'FireHOL IP Deduplicator and Aggregator'
sc.exe start firehol-differ-nftables
```

Verify the service and inspect Windows Event Viewer or the service process logs if it
stops unexpectedly:

```powershell
sc.exe query firehol-differ-nftables
```

## Stop or uninstall

```powershell
sc.exe stop firehol-differ-nftables
sc.exe delete firehol-differ-nftables
Remove-Item 'C:\\Program Files\\firehol-differ-nftables\\firehol-differ-nftables.exe'
```

The WiX installer stops and removes the service during uninstall. The installed
configuration and generated data under `C:\\ProgramData\\firehol-differ-nftables`
are retained.
