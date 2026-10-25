# Testing Veer with a real Mac

The first real test answers the question [PROTOCOL.md](PROTOCOL.md) leaves
open: **does a current Mac speak AirDrop over an ordinary network when
`BrowseAllInterfaces` is set?** Follow the steps in order and write down
what you see at each one, including failures; a failure at one step is
itself a result.

Time needed: about 30 minutes.

## 0. What you need

- The Windows PC with Veer, and a Mac, **on the same local network and the
  same subnet**: for example both on the home router, one by cable and one on
  Wi-Fi is fine. Guest Wi-Fi networks and "AP/client isolation" block the
  multicast this needs.
- An administrator account on both.
- Optional, for problems: [Wireshark](https://www.wireshark.org/) on the PC.

Write down the Mac's model and macOS version:

```sh
sw_vers
sysctl -n hw.model
```

## 1. Prepare the PC

All commands below are for PowerShell in the project folder.

1. **Install Veer** (once):

   ```powershell
   py -m venv .venv
   .venv\Scripts\python -m pip install -e .
   .venv\Scripts\veer --version
   ```

   The commands below write `veer`; use `.venv\Scripts\veer` unless the
   virtual environment is activated (`.venv\Scripts\Activate.ps1`).

2. **Set the network to Private.** Settings → Network & internet → Ethernet
   (or Wi-Fi) → *Network profile type* → **Private network**. Veer's
   firewall rules apply to Private networks only, on purpose.

3. **Add the firewall rules**, from a terminal opened with *Run as
   administrator*:

   ```powershell
   veer firewall add
   ```

   This adds two inbound rules, Private profile and local subnet only:
   `Veer - AirDrop HTTPS (TCP-In)` (TCP 8771) and `Veer - mDNS (UDP-In)`
   (UDP 5353). `veer firewall add --dry-run` prints them without adding.

4. **Check** (no administrator needed):

   ```powershell
   veer firewall show
   veer interfaces
   ```

   `firewall show` must list the network as `[Private]` and both rules. If it
   lists rules *blocking* `python.exe`, delete them in *Windows Defender
   Firewall with Advanced Security → Inbound Rules*: a block beats any allow.
   Windows creates those when its "Allow this app?" dialog is cancelled; if
   the dialog appears during the tests, tick **Private networks** only and
   press **Allow**.

   `interfaces` marks with `*` the interfaces Veer uses. If an unrelated one
   is marked (a VPN, Hyper-V, WSL), add `--iface Ethernet` (or `--iface Wi-Fi`)
   to every command below.

## 2. Prepare the Mac

1. **Enable AirDrop on every interface**, in Terminal:

   ```sh
   defaults write com.apple.NetworkBrowser BrowseAllInterfaces 1
   defaults read com.apple.NetworkBrowser
   killall Finder
   killall sharingd    # AirDrop's daemon; macOS restarts it at once
   ```

   If later steps show nothing at all, restart the Mac once and try again: we
   do not know when `sharingd` reads the setting.

2. Leave **Wi-Fi and Bluetooth on**, even if the Mac is on a cable: macOS
   may refuse to turn AirDrop on without them.

3. **AirDrop visible to everyone:** Control Center → AirDrop → **Everyone for
   10 Minutes**. Repeat it whenever the 10 minutes run out.

4. **Open a Finder window on AirDrop** (Finder → Go → AirDrop, or ⇧⌘R) and
   keep it open: a Mac may only look for and announce AirDrop while it is
   open.

5. **Mac firewall:** System Settings → Network → Firewall. If it is on,
   *Block all incoming connections* must be off.

6. Note the Mac's IP address and network interface:

   ```sh
   route -n get default | grep interface    # e.g. "interface: en0"
   ipconfig getifaddr en0                    # e.g. 192.168.1.20
   ```

## 3. Look from the Mac first

These use only Apple's tools and tell us what the Mac itself does. With the
AirDrop window open, in a second Terminal window:

```sh
dns-sd -B _airdrop._tcp local
```

Leave it running for 15 seconds, then Ctrl+C. Each line has an interface
index (`if`). Find out which index is which:

```sh
ifconfig | grep -E '^[a-z]|index'      # or: networksetup -listallhardwareports
```

**Write down:** which interfaces the Mac's own AirDrop instance appears on.
Only `awdl0` → the Mac is not announcing on the LAN (outcome 3 in
PROTOCOL.md). `en0`/`en1` as well → very good sign.

Then, with the instance name from that list (12 hex digits):

```sh
dns-sd -L <instance> _airdrop._tcp local
sudo lsof -nP -iTCP -sTCP:LISTEN | grep -i sharingd
```

The first prints the port and the full TXT record; the second which address
the AirDrop server listens on (`*:8770` means every interface).

## 4. Test 1 — the PC finds the Mac (`veer discover`)

On the PC, with the Mac's AirDrop window open:

```powershell
veer -v discover --seconds 15 --save results\discover
```

What the outcomes mean:

| What `discover` prints | Meaning |
|---|---|
| The Mac listed, `/Discover` → `HTTP 200` with `ReceiverComputerName` | **Discovery works.** Go on. |
| The Mac listed, `/Discover` fails (timeout, TLS error, refused) | It announces on the LAN but does not serve there, or a firewall blocks. Copy the error. |
| Not listed, but "N multicast DNS responses heard" with N > 0 | mDNS reaches the PC, but the Mac does not announce AirDrop on the LAN. |
| Not listed and 0 responses heard | Nothing comes in at all: check step 1 (Private network, rules) first. |

If the Mac is not listed but step 3 showed it listening, ask it directly
with its IP address (port from step 3, usually 8770):

```powershell
veer -v discover --address 192.168.1.20:8770
```

**Send me:** the whole output, and the files in `results\discover`.

## 5. Test 2 — the Mac sends to the PC (`veer receive`)

On the PC:

```powershell
veer -v receive
```

It prints the name the Mac should show (by default `<PC name> (Veer)`) and
where files go (`Downloads\Veer`).

On the Mac:

1. In the Finder AirDrop window, does the PC appear? Wait up to 30 s. In
   Terminal, `dns-sd -B _airdrop._tcp local` should also list Veer's
   instance on `en0`. **Write down** both.
2. Drag a small text file onto the PC's icon. The PC console asks
   `Accept? [y/N]`: type `y` and Enter.
3. **Write down exactly what the Mac shows**, especially if it asks for or
   shows an **AirDrop code**, or says the transfer failed.
4. On the PC, check the file and its Mark of the Web:

   ```powershell
   Get-ChildItem $HOME\Downloads\Veer
   Get-Content -Stream Zone.Identifier $HOME\Downloads\Veer\<file>
   ```

   The second must print `ZoneId=3`.
5. Send again and answer `n`. Write down what the Mac says on a refusal.
6. Send a photo from Photos. Note whether it arrives as `.jpg` (converted)
   or `.heic`.

Stop the receiver with Ctrl+C.

## 6. Test 3 — the PC sends to the Mac (`veer send`)

With the Mac's AirDrop window open:

```powershell
veer -v send C:\path\to\file.txt --to "<part of the Mac's name>"
```

1. The Mac should show a request from `<PC name> (Veer)`. **Write down**
   whether it is the usual Accept/Decline, or asks for an **AirDrop code**.
2. Accept: the file goes to the Mac's Downloads. Then try once declining.
3. If it fails, or a code is asked for, run it again with `--trace` instead
   of `-v` and keep the whole output.

If the Mac is not found but test 1 worked with `--address`, use the same
address here: `veer -v send file.txt --address 192.168.1.20:8770`.

## 7. Logs when something fails

**On the PC**, `--trace` prints every mDNS record, HTTP header and plist.
Save it with:

```powershell
veer --trace receive 2>&1 | Tee-Object -FilePath veer-receive.log
veer --trace send file.txt --to Mac 2>&1 | Tee-Object -FilePath veer-send.log
```

**On the Mac**, start this before the test, Ctrl+C after it:

```sh
log stream --info --debug --style compact \
  --predicate 'subsystem == "com.apple.sharing" OR process == "sharingd"' > sharing.log
```

or afterwards, for the last ten minutes:

```sh
log show --last 10m --info --debug --style compact \
  --predicate 'subsystem == "com.apple.sharing" OR process == "sharingd"' > sharing.log
```

The logs contain device names, IP addresses and possibly hashed contact
details: look through them before sharing them, and do not publish them.

## 8. Packet captures

**On the PC**, with Wireshark (it installs Npcap): capture on the Ethernet or
Wi-Fi interface with the capture filter

```
udp port 5353 or tcp port 8770 or tcp port 8771
```

and look at it with the display filter `mdns || tcp.port in {8770 8771}`.
mDNS is readable as is; the HTTPS is not. To decrypt Veer's side of it, set
`SSLKEYLOGFILE` before running Veer:

```powershell
$env:SSLKEYLOGFILE = "$PWD\tls-keys.log"
veer --trace send file.txt --to Mac
```

and in Wireshark: Preferences → Protocols → TLS → *(Pre)-Master-Secret log
filename* → that file. Delete the file afterwards: it decrypts the capture.

**On the Mac**, the same traffic:

```sh
sudo tcpdump -i en0 -w mac.pcap 'udp port 5353 or tcp port 8770 or tcp port 8771'
```

## 9. Undo the Mac setting

```sh
defaults delete com.apple.NetworkBrowser BrowseAllInterfaces
killall Finder; killall sharingd
```

## What to report

For each step: what you ran, what it printed (copied, not paraphrased), what
the Mac showed (a screenshot is best), and the macOS version from step 0.
