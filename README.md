# Veer

Veer is an open source tool for Windows 11 that exchanges files with Macs
using the AirDrop protocol over the local network (Wi-Fi or Ethernet), with no
extra hardware.

> **Status:** early research. A command-line prototype exists and works
> between two copies of Veer; it has not yet been tried against a real Mac.
> Nothing here is ready for everyday use.

## How it works, in one paragraph

AirDrop normally runs over AWDL, Apple's proprietary peer-to-peer Wi-Fi link,
which Windows cannot speak. A Mac can be told to look for and announce AirDrop
over every network interface instead
(`defaults write com.apple.NetworkBrowser BrowseAllInterfaces 1`). Veer relies
on that: it uses ordinary multicast DNS (`_airdrop._tcp`) and HTTPS on the LAN
the PC and the Mac already share. See [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Scope

- Macs only. iPhone and iPad do not do AirDrop over a LAN.
- The Mac must be set to receive from **Everyone for 10 Minutes**.
  "Contacts Only" needs Apple-signed certificates and is out of scope.

## Try it

Python 3.10 or newer on Windows 11:

```powershell
py -m venv .venv
.venv\Scripts\python -m pip install -e .
.venv\Scripts\veer --help
```

| Command | What it does |
|---|---|
| `veer discover` | Looks for Macs announcing AirDrop and prints everything they say |
| `veer send FILE... [--to NAME]` | Asks a Mac to accept the files, then sends them |
| `veer receive` | Shows this PC to Macs; asks in the console before accepting anything |
| `veer interfaces` | Lists the network interfaces Veer can use (`--iface` picks them) |
| `veer firewall show\|add\|remove` | Checks or manages Veer's Windows Firewall rules |

The PC's network must be set to **Private**, and Veer's firewall rules added
once from an elevated prompt (`veer firewall add`). The full procedure,
including the Mac side, is in [docs/TESTING-MAC.md](docs/TESTING-MAC.md).

Received files go to `Downloads\Veer`. Veer never opens them, and marks each
one as downloaded from the Internet, so Windows warns before running it.
Anyone on the local network can *offer* files while `veer receive` runs;
nothing is stored without a "y" in the console.

## Tests

```powershell
.venv\Scripts\python -m unittest discover -s tests
```

They run a sender against a receiver over the loopback interface, in one
process and as two separate `veer` processes found over multicast DNS. No
network or Mac is needed.

## What Veer leaves on the PC, and how to remove it

| What | Where | Remove with |
|---|---|---|
| TLS certificate and key | `%LOCALAPPDATA%\Veer\keys` (or `%VEER_HOME%\keys`) | delete `%LOCALAPPDATA%\Veer` |
| Received files | `Downloads\Veer` (or `--outdir`, `%VEER_DOWNLOAD_DIR%`) | delete them as usual |
| Firewall rules `Veer - AirDrop HTTPS (TCP-In)`, `Veer - mDNS (UDP-In)` | Windows Defender Firewall | `veer firewall remove` (elevated) |
| An "Allow" or "Block" rule for `python.exe`, if Windows asked | Windows Defender Firewall | *Windows Defender Firewall with Advanced Security* → Inbound Rules |

## Disclaimer

Veer is an independent project. It is not affiliated with, authorized,
sponsored or endorsed by Apple Inc. AirDrop, Mac, macOS, iPhone and iPad are
trademarks of Apple Inc., registered in the U.S. and other countries.

## License

MIT, see [LICENSE](LICENSE). Parts are adapted from
[winawdl](https://github.com/raph559/winawdl) and
[omdrop](https://github.com/brentkearney/omdrop-plugin), both MIT; their
notices are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
