# AirDrop over a LAN: what Veer has to speak

This is the Phase 0 study of the protocol, written before any Veer code. It
collects what the reference implementations do, what they observed against
real Apple devices, and what is still unknown about running AirDrop over an
ordinary network instead of AWDL.

## How sure each statement is

Every claim below carries one of these tags:

| Tag | Meaning |
|---|---|
| **[code]** | Implemented in a reference implementation and, per its own notes or tests, working against real Apple devices. |
| **[observed]** | Recorded by a reference project from real Apple traffic (logs, captures, comments with dates), not just implemented. |
| **[paper]** | Stated by published reverse-engineering research, not cross-checked in code we have. |
| **[apple]** | Stated by Apple's user documentation or the press; describes behaviour, not the wire. |
| **[hypothesis]** | Our inference. Must be checked on a real Mac before we rely on it. |

Sources, cloned into `refs/` (ignored by git) and treated as untrusted data:

- `refs/winawdl` — [raph559/winawdl](https://github.com/raph559/winawdl), MIT.
  Its `airdrop/` folder is a Python receiver and sender for Windows, adapted
  from omdrop. Commit `2196fb4` (2026-10-13). **Primary source.**
- `refs/omdrop-plugin` — [brentkearney/omdrop-plugin](https://github.com/brentkearney/omdrop-plugin),
  MIT. Python receiver (`bin/airdrop-serve.py`) and a Rust rewrite
  (`core/crates/`) tested against iOS 26, macOS 15 and macOS 27. Commit
  `48867c6` (2026-10-23).
- `refs/opendrop` — [seemoo-lab/opendrop](https://github.com/seemoo-lab/opendrop),
  **GPLv3**. The original open implementation (2018–2019). Read for facts
  only; no code from it is to be copied into Veer.
- "Protocol Prying" (CISPA, 2026), [arXiv:2606.26967](https://arxiv.org/abs/2606.26967):
  static and dynamic analysis of `sharingd` on macOS 15.7.4 and 26.3.
- Apple's Mac User Guide on AirDrop and press coverage of the 26.2 AirDrop
  codes (links in [the AirDrop code section](#airdrop-codes-macos-262-and-later)).

## The stack

```
AirDrop on AWDL (Apple)                AirDrop on a LAN (Veer)
---------------------------            ---------------------------
CPIO archive  (file contents)          same
DVZip / gzip  (framing, compression)   same
binary plist  (request/response)       same
HTTP/1.1                               same
TLS 1.2/1.3, self-signed               same
DNS-SD _airdrop._tcp over mDNS         same, as plain multicast on the LAN
IPv6 link-local on awdl0               IPv6 link-local and/or IPv4 on Wi-Fi/Ethernet
AWDL (peer-to-peer Wi-Fi)              the existing LAN
BLE advertisement (wake-up)            not available / maybe not needed  [hypothesis]
```

Everything from mDNS upwards is the same protocol regardless of the link;
that is the whole bet Veer makes. The parts that change are at the bottom
and are discussed in [AWDL versus LAN](#awdl-versus-lan).

## 1. Discovery: mDNS / DNS-SD

### Records a receiver announces

A receiver publishes one DNS-SD instance of `_airdrop._tcp.local.` **[code]**
(winawdl `mdns.py`, omdrop `omdrop-adv/src/frames.rs`, OpenDrop via
`zeroconf`):

| Record | Name | Value |
|---|---|---|
| PTR | `_airdrop._tcp.local` | `<service-id>._airdrop._tcp.local` |
| SRV | `<service-id>._airdrop._tcp.local` | priority 0, weight 0, port, `<host>.local` |
| TXT | `<service-id>._airdrop._tcp.local` | `flags=<decimal>` |
| AAAA | `<host>.local` | the interface's IPv6 link-local address |
| NSEC | `<host>.local` | "only AAAA and NSEC exist" |

- `<service-id>` is 12 lowercase hex digits (6 random bytes), e.g.
  `0e9d036c5823` **[code]**, matching what real devices use **[observed]**
  (omdrop `omdrop-send/src/aflog.rs` quotes an Apple SRV:
  `0e9d036c5823._airdrop._tcp.local -> port 8770, hume.local`). It is the
  same value the sender later puts in `SenderID`.
- The NSEC record exists because Apple devices also ask for an A record of an
  IPv6-only host and keep waiting otherwise; the NSEC tells them there is
  none **[observed]** (omdrop, carried into winawdl).
- TTLs used by the references: 4500 s for PTR/TXT, 120 s for SRV/AAAA/NSEC,
  with the cache-flush bit on the unique records; a goodbye (TTL 0) on stop
  **[code]**.
- Apple devices listen on **TCP 8770** **[observed]** (omdrop logs of
  iPhones and Macs; the paper also says 8770). OpenDrop and winawdl default
  to 8771 for their own receiver; any port works because the SRV carries it
  **[code]**.
- The paper says Apple's own TXT record has "about 25 keys" **[paper]**. The
  references publish only `flags` and are accepted by iPhones and Macs
  **[observed]**, so `flags` is the only one Veer needs to publish. When
  *browsing*, Veer should log the full TXT of each Mac it finds: that tells
  us what we are missing.

### The `flags` TXT key

A bit mask of receiver capabilities, recovered from `sharingd`'s
`receiverSupportsX` methods (OpenDrop's `config.py`, facts restated here, not
code) **[paper/code]**:

| Bit | Name | Notes |
|---|---|---|
| `0x001` | SUPPORTS_URL | Links arrive in the Ask itself, with no Upload |
| `0x002` | SUPPORTS_DVZIP | Upload may be `application/x-dvzip` |
| `0x004` | SUPPORTS_PIPELINING | |
| `0x008` | SUPPORTS_MIXED_TYPES | |
| `0x010` | unknown | |
| `0x020` | unknown | |
| `0x040` | SUPPORTS_IRIS | Live Photos, presumably |
| `0x080` | probably "supports /Discover" | |
| `0x100` | unknown | |
| `0x200` | SUPPORTS_ASSET_BUNDLE | |
| `0x800` (bit 11) | SupportsUPP: Upload without a prior Ask | **[paper]** only |

- A sender drops a receiver that has neither PIPELINING nor MIXED_TYPES
  (`[SDBonjourBrowser removeInvalidNodes:]`) **[code comment, OpenDrop]**.
- macOS's own default is `0x3fb` = 1019 (`[SDRapportBrowser
  defaultSFNodeFlags]`) **[code comment]**. winawdl and omdrop advertise
  `0x3fb` and are accepted **[observed]**; OpenDrop advertised only
  `0x88`. Veer will advertise `0x3fb` like winawdl, and may need to clear
  bits for features it does not implement (e.g. `0x001` if links are not
  stored, `0x040`/`0x200` if those formats are not handled) **[hypothesis]**.

### What a browser does

- Send a query for `_airdrop._tcp.local` PTR, then SRV for each instance
  whose location is not yet known; repeat every ~0.5 s **[code]** (winawdl
  `mdns.Browser`).
- An instance is "located" once PTR + SRV are known; the address is the AAAA
  if any, else the source address of the response **[code]**.
- The Mac may present several instance names over time (a new random id per
  session); dedupe by address **[code]** (winawdl `Instances.devices`).

## 2. Transport: TLS

- HTTPS on the SRV port. TLS 1.2 or 1.3 **[paper]**; the references require
  at least TLS 1.1 (omdrop) and work with the defaults of Python's `ssl`
  **[code]**.
- **Both sides use self-signed certificates and verify nothing** in Everyone
  mode: no hostname check, no chain check **[code]** (winawdl
  `client_context`/`tls_context`; OpenDrop: "we accept self-signed
  certificates as does Apple"). The certificate's subject does not matter
  ("Senders do not look at the name", winawdl `identity.py`) **[code]**.
- The sender presents a client certificate. An Apple sender signed in to
  iCloud presents an Apple-issued one, used by a Contacts Only receiver
  together with `SenderRecordData` **[observed]** (omdrop: "a sender presents
  its Apple-issued client certificate on /Ask and never on /Discover"). The
  paper says no client certificate is used; omdrop's captures contradict
  that for the Contacts Only case. Veer presents its self-signed one as a
  client, as winawdl does.
- A receiver that wants contacts only can end the handshake with a
  `certificate unknown` alert to a self-signed client **[observed]** (winawdl,
  from an iPhone; "likely and not established" that this is the Contacts
  Only behaviour).
- The handshake should run on the connection's own thread: done in `accept()`,
  one peer stalling mid-handshake blocked every later connection **[observed]**
  (omdrop, 2026-09-30).
- Certificate generation: winawdl and OpenDrop shell out to `openssl req
  -newkey rsa:2048 -nodes -x509 -days 365`; winawdl finds the OpenSSL that
  Git for Windows ships **[code]**. Python's standard library cannot create
  a certificate, so Veer must either do the same or depend on
  `cryptography`. Decided: Veer depends on `cryptography`, so that it does
  not need Git for Windows or any other OpenSSL installation.

## 3. HTTP/1.1

Common to all requests **[code]** (OpenDrop, omdrop `HEADERS`):

```
POST /Discover HTTP/1.1
Content-Type: application/octet-stream
Connection: keep-alive
Accept: */*
User-Agent: AirDrop/1.0
Accept-Language: en-us
Accept-Encoding: br, gzip, deflate
```

- `sharingd` (macOS 15, iOS 26) sends `/Discover` and `/Ask` bodies with
  `Transfer-Encoding: chunked` and **no** `Content-Length` **[observed]**
  (omdrop). A receiver must read chunked bodies; OpenDrop's
  `int(Content-Length)` breaks.
- **`/Ask` and `/Upload` go over the same TLS connection.** An Upload on a
  separate connection is rejected **[paper]**, and the references tie the
  upload to the accepted ask per connection **[code]**.
- `/Upload` may carry `Expect: 100-continue`; the references answer 100 only
  after validating framing and size **[code]**.
- `GET` and `HEAD` are answered with a bare 200 **[code]** (purpose unknown).
- The paper lists seven POST endpoints: `/Discover`, `/Hello`, `/Ask`,
  `/Upload`, `/Exchange`, `/SharedIdentity`, `/Error` **[paper]**. Nothing in
  the references uses the last four; they answer them 400 and nothing has
  complained. Their meaning is unknown (see the AirDrop code section).

### 3.1 `POST /Discover`

Sender → receiver, "who are you?".

Request body (binary plist dictionary), all optional:

| Key | Type | Notes |
|---|---|---|
| `SenderRecordData` | data | Apple ID validation record (CMS, ~3.7 kB from a Mac). Only for Contacts Only. **[observed]** |
| `DeviceSupportFlags` | integer | A Mac sends it; omdrop's sender uses `111611`. Meaning not documented. **[code]** |

winawdl's sender sends an empty dictionary and gets answers from iPhones
**[observed]**.

Response 200, binary plist:

| Key | Type | Notes |
|---|---|---|
| `ReceiverComputerName` | string | Name shown under the tile. **Absent → the receiver is not visible to us** (contacts only). **[code]** |
| `ReceiverModelName` | string | Apple model id, e.g. `MacBookPro18,3`; picks the icon. **[code]** |
| `ReceiverMediaCapabilities` | data | UTF-8 JSON, see below. **[code]** |
| `IsAirDropable` | bool | `true`; seen in real Mac answers, added by omdrop 2026-10-11. **[observed]** |
| `ReceiverRecordData` | data | Contacts Only only. |

The paper reports status codes 200 (contacts matched), 401 (contacts only,
no match) and "100 (Everyone)" **[paper]**; the last is odd for HTTP and
unconfirmed. The references treat any non-200 or a missing name as "not
visible".

`ReceiverMediaCapabilities` is JSON in a data blob. `{"Version": 1}` with no
codecs makes the sender convert to legacy formats (JPEG rather than HEIC)
**[code]** (OpenDrop, winawdl). omdrop now sends a `Version: 3` table captured
from a MacBook Pro **[observed]**. Veer wants the legacy conversion, so
`{"Version": 1}` is the right choice for Windows.

### 3.2 `POST /Ask`

Sender → receiver, "may I send these?". The receiver holds the response
until its user accepts or declines.

Request body, as winawdl and omdrop's Rust sender build it after copying
what real Apple senders send **[observed]**:

| Key | Type | Notes |
|---|---|---|
| `TransferID` | dict `{"id": "<UUID, upper case>"}` | Also sent as the `TransferID` header of the Upload. |
| `TransferType` | dict | `{"files": {}}` or `{"links": {}}` |
| `SenderID` | string | The 12-hex service id. |
| `SenderComputerName` | string | Shown in the receiver's prompt. |
| `SenderModelName` | string | e.g. `MacBookPro18,3`. |
| `BundleID` | string | `com.apple.finder` for files, `com.apple.Safari` for links. |
| `Items` | array | Empty for files; the URLs for links. |
| `Files` | array of dicts | One per file, below. |
| `ConvertMediaFormats` | bool | `false` |
| `FileIcon` | data | Optional preview (JPEG/JPEG 2000). |
| `SenderRecordData` | data | Contacts Only only. |
| `SenderIdentityAuthTag` | data (3 bytes) | A Mac's own Ask has it; "binds the HTTP sender to its BLE presence". Optional for Everyone. **[observed]** (omdrop, 2026-09-08) |

Each `Files` entry:

| Key | Type | Example |
|---|---|---|
| `FileName` | string | `photo.jpg` |
| `FileType` | string (UTI) | `public.jpeg`, `com.adobe.pdf`, fallback `public.data` |
| `FileSize` | integer | bytes |
| `FileBomPath` | string | `./photo.jpg` |
| `FileIsDirectory` | bool | |
| `ConvertMediaFormats` | bool | `false` |
| `ShouldConvertMediaFormats` | bool | `false` (iPhone sends it) |

An iPhone accepted the request but dropped the upload when the Ask lacked
`TransferID` and `FileSize` and the upload was OpenDrop-shaped **[observed]**
(winawdl DESIGN-NOTES, 2026-10-11; which of the four differences mattered was
not isolated).

Response:

- **Accepted:** 200 with the same keys as the Discover answer
  (`ReceiverComputerName`, `ReceiverModelName`, `ReceiverMediaCapabilities`,
  `IsAirDropable`) **[observed]** (omdrop: answering with only the two name
  keys made iOS 26 skip the upload of a link).
- **Declined:** winawdl answers **401**, "not checked against an iPhone";
  omdrop answers 403 for a Contacts Only refusal **[code]**. What a Mac
  returns when its user declines is unknown. Veer's sender should treat
  every non-200 as "declined" and log the status.
- **Timeout:** the paper says the Ask waits up to 15 s **[paper]**; winawdl
  waits 90 s for the user **[code]**. To be measured against a Mac.
- **Links:** for `TransferType: links` the URLs are in `Items` and there is
  no Upload: accepting the Ask is the transfer **[observed]**.

### 3.3 `POST /Upload`

Sender → receiver, on the Ask's connection, after a 200.

```
POST /Upload HTTP/1.1
Content-Type: application/x-dvzip
TransferID: <the Ask's UUID>
TotalBytes: <sum of FileSize>
Transfer-Encoding: chunked
```

**[observed]** (sharingd's upload as seen by omdrop's receiver, "093540Z").

- Older senders (iOS 16, OpenDrop) send `application/x-cpio` with a gzip
  body. Answering 406/415 to either makes the sender report failure, so a
  receiver accepts both **[observed]**. A Mac's `sharingd` rejects
  OpenDrop's x-cpio+gzip upload with 406 **[observed]** (omdrop), so Veer's
  sender must send DVZip.
- `TotalBytes` is the only size for a Live Photo, whose Ask declares 0 bytes
  **[observed]**.
- Response: 200 with an empty body once the files are stored.
- **The end of the body is unreliable:**
  - An iPhone may send every chunk and never the closing `0` chunk
    **[observed]** (winawdl, omdrop). Receivers decode the archive as it
    arrives and accept it once the CPIO trailer and padding are in.
  - A Mac's `sharingd` (macOS 27) sends the closing `0` chunk only *after* it
    has the answer, and reports failure if the receiver closes with that chunk
    unread (RST → `NSPOSIXErrorDomain 54`) **[observed]** (omdrop test,
    2026-10-11). The receiver must answer, then drain until the peer closes.

## 4. Payload: the archive

### DVZip framing

A sequence of blocks, each preceded by a 4-byte big-endian header **[code]**:

- top bit (`0x80000000`) set → the block is stored as is; the low 31 bits are
  its length;
- otherwise the low 31 bits are the length of one complete zlib stream.

A body that starts with `1f 8b` is gzip instead **[code]**. winawdl's sender
cuts the archive into 16 KiB blocks at zlib level 1 and stores a block raw
when compression does not shrink it **[code]**; iPhones and Macs accept that
**[observed]**.

### CPIO

The decoded stream is a CPIO archive **[code]**:

- Readers must accept the portable ASCII format (`070707`, "odc") and the
  "new ASCII" ones (`070701`, `070702`) **[code]**. omdrop says sharingd sends
  odc; the paper says newc **[paper]**. Possibly both, depending on version;
  Veer reads all three and writes odc, as winawdl does.
- The archive starts with a `.` directory, then `./<name>` members **[observed]**
  (iPhone; winawdl copied it for its sender).
- It ends with a `TRAILER!!!` entry, then zero padding to a multiple of 512
  bytes **[code]**.
- Members to skip when receiving: AppleDouble companions `._name` (Finder
  metadata), directories as entries; a Live Photo arrives as a `*.pvt` folder
  with a still, a `.mov` and `metadata.plist` **[observed]**.

Everything here is attacker-controlled: names (path separators, `..`, Windows
device names, reserved characters, bidi overrides), sizes, member counts,
decompression ratio, plist reference expansion. winawdl's `transfer.py`
bounds each of these and is the model to follow **[code]**. The paper found
pre-authentication crashes in Apple's own parser, which is a reminder that
this surface is reachable by anyone in range **[paper]**.

## 5. AWDL versus LAN

What the references do relies on AWDL. What changes on a LAN is mostly
**unverified**, and most of it is exactly what `veer discover` is meant to
find out.

| Topic | On AWDL (references) | On a LAN (Veer) |
|---|---|---|
| Interface | `awdl0`, IPv6 link-local only | Wi-Fi or Ethernet, IPv4 and IPv6 |
| Addressing | `fe80::…%awdl0`, needs the scope id | Link-local IPv6 still needs the scope id on Windows; IPv4 does not |
| mDNS transport | iPhones carry their records in AWDL action frames, not multicast; winawdl's daemon turns them into mDNS **[observed]** | Ordinary multicast to `224.0.0.251` / `ff02::fb` port 5353 **[hypothesis]** |
| Address family | IPv6 only | Unknown whether a Mac announces A, AAAA or both on a LAN **[hypothesis: both]**; Veer should browse and announce on both |
| Wake-up | An iPhone announces only after a BLE "AirDrop" advertisement (Apple manufacturer data, type 5, four 2-byte contact hashes) **[observed]** | Unknown whether a Mac announces on the LAN all the time while discoverable, only while a Finder AirDrop window/share sheet is open, or only after a BLE wake. **Main open question.** |
| Multicast timing | AWDL drops multicast outside its slots, so announcements repeat every 2 s **[observed]** | Normal mDNS timing should suffice; repeating is harmless |
| Firewall | Rules for link-local on `awdl0` | Inbound TCP (our port) and UDP 5353 on the Private profile, local subnet only |
| Throughput | 1–16 MB/s, radio-bound | Should be LAN speed |

### `BrowseAllInterfaces`: what it historically did

`defaults write com.apple.NetworkBrowser BrowseAllInterfaces 1` (then relaunch
Finder) dates from OS X Lion (2011). Guides of that era say it makes AirDrop
work over Ethernet and on unsupported Macs, **but in the legacy AirDrop
mode**: the other Mac had to use "Search for an Older Mac", and discovery was
limited to one subnet because it is Bonjour **[apple]** (press guides from
2011–2014), e.g.
[OSXDaily](https://osxdaily.com/2011/09/16/enable-airdrop-ethernet-and-unsupported-macs/),
[Univ. of Utah Marriott Library](https://apple.lib.utah.edu/airdrop-how-to-enable-on-os-x-mavericks-via-ethernet/).
We found no source confirming what the key does on macOS 26 or 27.

The "Search for an Older Mac" button disappeared from Finder years ago.
Three outcomes are possible **[hypothesis]**:

1. The key still makes `sharingd` browse and announce `_airdrop._tcp` on all
   interfaces with the modern protocol. Veer works as designed.
2. It works for browsing only (or announcing only). Veer works in one
   direction; the other needs another approach.
3. It is ignored. Veer's LAN design does not work, and the alternatives are
   a radio-level AWDL implementation (as winawdl does, card-specific and
   GPL-tainted) or something else entirely.

Telling these apart is the first thing `veer discover` and the Mac test
script are for. Useful checks on the Mac: `dns-sd -B _airdrop._tcp` (does
the Mac's own browser see Veer's announcement on `en0`?), `dns-sd -L <id>
_airdrop._tcp` (does the Mac announce itself, on which interface?), and
`log stream --predicate 'subsystem == "com.apple.sharing"'`.

## 6. Certificates and identity

- Everyone mode: a self-signed RSA-2048 certificate on each side, any subject,
  regenerated if missing **[code]**.
- Contacts Only needs an Apple-issued certificate plus the matching validation
  record (`SenderRecordData` / `ReceiverRecordData`, a CMS blob holding hashes
  of the account's phone numbers and e-mail addresses). omdrop obtains one
  from an Apple account **[code]**. **Out of scope for Veer.**
- The record's hashes are reversible to phone numbers by brute force; nothing
  of it should be logged **[code comment, omdrop]**.

## AirDrop codes (macOS 26.2 and later)

### What Apple says **[apple]**

From macOS/iOS/iPadOS 26.2, when someone who is **not in your contacts**
sends to you while you are in **Everyone (for 10 Minutes)**:

1. You click Accept, then "Get AirDrop Code" if asked; your device shows a
   code.
2. You give the code to the sender, who types it on their device.
3. The item is sent. For the next **30 days** the two can AirDrop without a
   new code; the sender appears in an **"Other Known"** list in Contacts and
   can be removed with "Forget This Person".

Both devices must run a 26.2 release for this to apply.

Sources: [Apple, Mac User Guide](https://support.apple.com/guide/mac-help/use-airdrop-to-send-items-to-nearby-devices-mh35868/mac),
[Six Colors](https://sixcolors.com/post/2025/12/airdrop-codes-allow-temporary-persistent-contact/),
[9to5Mac](https://9to5mac.com/2026/01/14/ios-26-2-added-new-airdrop-upgrade-feature-heres-how-it-works/),
[iDownloadBlog](https://www.idownloadblog.com/2026/01/13/airdrop-contacts-iphone/).

### What is known about the wire

**Nothing, so far.** None of the three reference implementations mentions the
code. The paper (macOS 26.3) does not describe it, but lists `/Hello`,
`/Exchange`, `/SharedIdentity` and `/Error` beside the classic endpoints
**[paper]**; an "exchange" of a "shared identity" fits the 30-day "Other
Known" contact suspiciously well **[hypothesis]**.

### What the references' results imply **[hypothesis]**

- **Mac → Veer (Veer receives):** omdrop's receiver, which knows nothing
  about codes, stored a transfer from a Mac on **macOS 27** on 2026-10-11 in
  Everyone mode **[observed]**. The code is shown by the *receiver*; a
  receiver that does not offer the feature apparently gets the pre-26.2 flow.
  Most likely the capability is negotiated (a TXT key, a `flags` bit,
  `DeviceSupportFlags`, or a key in the Discover answer) and Veer, not
  advertising it, is treated as an older device. **Expected to work.**
- **Veer → Mac (Veer sends):** the Mac is the one that would show a code.
  If the Mac sees Veer as a pre-26.2 sender, it should fall back to the old
  Accept/Decline prompt, as Apple says both sides need 26.2. If instead the
  Mac demands a code from every unknown sender, the Ask will come back with
  some new status or keys, or the Mac will expect one of the new endpoints.
  **Unknown; must be tested.** If it happens, the plan is:
  1. log the full Ask response (status, headers, plist) and the Mac's
     `com.apple.sharing` log;
  2. capture the exchange between two real Macs on 26.2+ (only possible on
     AWDL with keys from the Mac, or over the LAN if the Macs use it), to
     learn the request that carries the code;
  3. only then decide whether Veer can prompt for the code in the console.

## Implications for Veer's Phase 1

- Reuse winawdl's approach (MIT): plain-socket mDNS, bounded HTTP/TLS
  handling, DVZip + odc CPIO writer, CPIO reader for all three formats,
  Windows-safe names and the Mark-of-the-Web. Adapt it to IPv4 + IPv6 on LAN
  interfaces instead of `awdl0`.
- No BLE in Phase 1. If a Mac only announces after a BLE wake, that is a
  finding, and BLE advertising from Windows is possible (winawdl does it
  through the WinRT Bluetooth API from PowerShell).
- `veer discover` prints everything it hears: the full TXT record, every
  address, and the full Discover answer, so the first Mac test gives us
  the missing facts above.
- Port 5353 on Windows: other programs share it (on this PC, Spotify on
  `0.0.0.0:5353` and Steam on `[::]:5353`; Windows' own mDNS responder in
  `dnscache` may too). Sharing needs `SO_REUSEADDR` on every socket; to be
  verified in Phase 1 that both Veer and the system resolver still receive
  the multicast responses.

## Licensing note

Everything Veer is planned to derive code from (winawdl's `airdrop/`,
omdrop) is MIT. OpenDrop (GPLv3) is used here only as a source of facts — the
flag names and meanings, the record layout — which are not copyrightable
expression; no OpenDrop code is copied. So Veer can be MIT, carrying
winawdl's and omdrop's MIT notices for the adapted parts.
