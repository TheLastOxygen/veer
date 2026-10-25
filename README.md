# Veer

Veer is an open source tool for Windows 11 that exchanges files with Macs
using the AirDrop protocol over the local network (Wi-Fi or Ethernet), with no
extra hardware.

> **Status:** early research. Nothing here is ready for everyday use yet.

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

## Disclaimer

Veer is an independent project. It is not affiliated with, authorized,
sponsored or endorsed by Apple Inc. AirDrop, Mac, macOS, iPhone and iPad are
trademarks of Apple Inc., registered in the U.S. and other countries.

## License

To be decided (see the Phase 0 notes); MIT is the current proposal.
