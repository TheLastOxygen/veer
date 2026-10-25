# SPDX-License-Identifier: MIT
"""The `veer` command."""
import argparse
import http.client
import json
import logging
import os
import re
import sys
import time

from . import APP_NAME, __version__, config, firewall, identity, mdns, netif, receiver, sender

log = logging.getLogger('veer')

EXIT_FAILED, EXIT_USAGE, EXIT_DECLINED = 1, 2, 3
MODEL_RE = re.compile(r'^[A-Za-z]+[0-9]+,[0-9]+$')
# What the receiver flag bits mean, as far as is known (docs/PROTOCOL.md).
FLAG_NAMES = {0x001: 'URL', 0x002: 'DVZIP', 0x004: 'PIPELINING', 0x008: 'MIXED_TYPES',
              0x010: 'UNKNOWN_0x10', 0x020: 'UNKNOWN_0x20', 0x040: 'IRIS',
              0x080: 'DISCOVER?', 0x100: 'UNKNOWN_0x100', 0x200: 'ASSET_BUNDLE',
              0x400: 'UNKNOWN_0x400', 0x800: 'UPP?'}


def flag_names(value):
    names = [name for bit, name in FLAG_NAMES.items() if value & bit]
    rest = value & ~sum(FLAG_NAMES)
    if rest:
        names.append(f'other {rest:#x}')
    return ', '.join(names) or 'none'


def say(text=''):
    print(text, flush=True)


def interfaces_from(args):
    try:
        chosen = netif.select(args.iface)
    except LookupError as error:
        raise SystemExit(f'{APP_NAME}: {error}') from None
    if not chosen:
        raise SystemExit(f'{APP_NAME}: no usable network interface; pick one with --iface '
                         '(see "veer interfaces")')
    return chosen


def warn_public_networks(chosen):
    """Best effort: say so when an interface's network is Public, where the
    firewall rules Veer needs do not apply."""
    if sys.platform != 'win32':
        return
    try:
        profiles = firewall.network_profiles()
    except Exception:
        return
    names = {i.name for i in chosen}
    for profile in profiles:
        if profile.get('InterfaceAlias') in names and profile.get('Category') == 'Public':
            say(f"Warning: the network on {profile.get('InterfaceAlias')} is set to Public. "
                'Set it to Private (Settings > Network & internet), or Macs cannot reach '
                'this PC.')


def describe_interfaces(chosen):
    return ', '.join(f'{i.name} ({", ".join(filter(None, [i.ipv4_address, i.link_local]))})'
                     for i in chosen)


def local_addresses():
    found = set()
    for interface in netif.all_interfaces():
        found.update(str(a.ip) for a in interface.ipv4 + interface.ipv6)
    return found


def bare_address(address):
    return address.split('%')[0]


# veer interfaces

def cmd_interfaces(args):
    for interface in netif.all_interfaces():
        mark = '*' if netif.usable(interface) else ' '
        say(f'{mark} {interface.summary()}')
    say('\n* = used unless --iface says otherwise')
    return 0


# veer discover

def print_discover_reply(reply, indent='      '):
    say(f'{indent}HTTP {reply.status} {reply.reason}')
    for header in ('Server', 'Content-Type'):
        if header in reply.headers:
            say(f'{indent}{header}: {reply.headers[header]}')
    answer = reply.plist()
    if answer is None:
        say(f'{indent}body: {len(reply.body)} bytes, not a plist: {reply.body[:80]!r}')
        return
    for key in sorted(answer):
        value = answer[key]
        if key == 'ReceiverMediaCapabilities' and isinstance(value, bytes):
            try:
                shown = json.dumps(json.loads(value), separators=(',', ':'))
            except ValueError:
                shown = f'<{len(value)} bytes, not JSON>'
            if len(shown) > 300:
                shown = shown[:300] + f'... ({len(shown)} chars)'
        elif isinstance(value, bytes):
            shown = f'<{len(value)} bytes>'
        else:
            shown = repr(value)
        say(f'{indent}{key}: {shown}')


def save_reply(directory, label, reply, extra):
    os.makedirs(directory, exist_ok=True)
    safe = re.sub(r'[^A-Za-z0-9._-]+', '_', label)
    with open(os.path.join(directory, f'discover-{safe}.plist'), 'wb') as out:
        out.write(reply.body)
    with open(os.path.join(directory, f'discover-{safe}.json'), 'w', encoding='utf-8') as out:
        json.dump({**extra, 'status': reply.status, 'reason': reply.reason,
                   'headers': reply.headers}, out, indent=2)


def discover_address(text, context, args):
    address, port = sender.split_address(text, 8770)
    say(f'POST /Discover to {address} port {port}')
    started = time.monotonic()
    try:
        reply = sender.discover_at(address, port, context)
    except (OSError, http.client.HTTPException) as error:
        say(f'      failed: {sender.describe_attempt(error)}')
        return False
    say(f'      answered in {(time.monotonic() - started) * 1000:.0f} ms')
    print_discover_reply(reply)
    if args.save:
        save_reply(args.save, f'{address}-{port}', reply, {'address': address, 'port': port})
    return reply.status == 200


def cmd_discover(args):
    context = identity.client_context(args.keys)
    if args.address:
        answered = [discover_address(text, context, args) for text in args.address]
        return 0 if any(answered) else EXIT_FAILED
    chosen = interfaces_from(args)
    warn_public_networks(chosen)
    say(f'Looking for AirDrop receivers for {args.seconds} s on {describe_interfaces(chosen)}')
    browser = mdns.Browser(config.SERVICE_TYPE, chosen)
    if args.trace:
        browser.on_record = lambda record, source, interface: log.debug(
            'record from %s on %s: %s %s ttl %d %r', source[0], interface.name, record.name,
            mdns.dns.TYPE_NAMES.get(record.rtype, record.rtype), record.ttl, record.value)
    seen = {}
    try:
        deadline = time.monotonic() + args.seconds
        while time.monotonic() < deadline:
            for peer in browser.poll(0.5):
                if peer.instance not in seen:
                    seen[peer.instance] = peer
                    log.info('heard %s on %s', peer.instance, peer.interface.name)
                else:
                    seen[peer.instance] = peer  # addresses may have filled in
    finally:
        browser.close()
    own = local_addresses()
    named = 0
    for number, peer in enumerate(seen.values(), start=1):
        this_pc = any(bare_address(a) in own for a in peer.addresses)
        say(f'\n[{number}] {peer.instance} on {peer.interface.name}'
            + ('  (this PC: a Veer receiver)' if this_pc else ''))
        say(f'    host:      {peer.host}, port {peer.port}')
        say(f'    addresses: {", ".join(peer.addresses) or "none"} (answer came from {peer.source})')
        txt = ' '.join(s.decode('utf-8', 'replace') for s in peer.txt_raw) or '(none)'
        say(f'    TXT:       {txt}')
        if peer.flags is not None:
            say(f'    flags:     {peer.flags} = {peer.flags:#x}: {flag_names(peer.flags)}')
        for address in peer.addresses:
            say(f'    POST /Discover to {address} port {peer.port}')
            started = time.monotonic()
            try:
                reply = sender.discover_at(address, peer.port, context)
            except (OSError, http.client.HTTPException) as error:
                say(f'      failed: {sender.describe_attempt(error)}')
                continue
            say(f'      answered in {(time.monotonic() - started) * 1000:.0f} ms')
            print_discover_reply(reply)
            if args.save:
                save_reply(args.save, f'{peer.instance_id}-{bare_address(address)}', reply,
                           {'instance': peer.instance, 'address': address, 'port': peer.port,
                            'interface': peer.interface.name, 'host': peer.host,
                            'txt': [s.decode('utf-8', 'replace') for s in peer.txt_raw]})
            answer = reply.plist() or {}
            if reply.status == 200 and answer.get('ReceiverComputerName'):
                named += 1
            break
    say(f'\n{len(seen)} AirDrop instance(s) announced, {named} answered with a name. '
        f'{browser.packets} multicast DNS response(s) heard in all.')
    if not seen:
        say('Nothing announced _airdrop._tcp here. On the Mac: AirDrop open in Finder and set to '
            '"Everyone for 10 Minutes", BrowseAllInterfaces set and Finder relaunched, same '
            'network as this PC. On this PC: "veer firewall show".')
        if browser.packets == 0:
            say('No multicast DNS response at all came in: the firewall is probably dropping '
                'it (UDP 5353 inbound).')
    return 0 if named else EXIT_FAILED


# veer send

def choose(named, wanted):
    if wanted:
        named = {name: r for name, r in named.items() if wanted.lower() in name.lower()}
    if not named:
        raise SystemExit(f'{APP_NAME}: no receiver found. On the Mac, set AirDrop to '
                         '"Everyone for 10 Minutes" and keep a Finder window on AirDrop open; '
                         'try "veer discover" for details.')
    if len(named) > 1:
        exact = [r for name, r in named.items() if wanted and name.lower() == wanted.lower()]
        if len(exact) == 1:
            return exact[0]
        raise SystemExit(f'{APP_NAME}: several receivers answer; pick one with --to: '
                         + ', '.join(sorted(named)))
    return next(iter(named.values()))


class SendProgress:
    def __init__(self):
        self._last = 0.0

    def accepted(self, total):
        say(f'Accepted. Sending {total / sender.MIB:.1f} MB...')

    def progress(self, done, total):
        now = time.monotonic()
        if now - self._last >= 0.5 or done >= total:
            self._last = now
            print(f'\r  {done * 100 // max(total, 1):3d}%  {done / sender.MIB:.1f} MB',
                  end='', file=sys.stderr, flush=True)
            if done >= total:
                print(file=sys.stderr, flush=True)


def cmd_send(args):
    try:
        files = sender.outgoing(args.files)
    except sender.Unsendable as error:
        raise SystemExit(f'{APP_NAME}: {error}') from None
    context = identity.client_context(args.keys)
    if args.address:
        address, port = sender.split_address(args.address, 8770)
        name = args.address
        try:
            found, _ = sender.identify(mdns.Peer('', None, '', port, (address,), {}, (), ''), context)
            if found:
                name = f'{found.name} ({found.model})'
        except (OSError, http.client.HTTPException):
            pass
    else:
        chosen = interfaces_from(args)
        warn_public_networks(chosen)
        say(f'Looking for receivers on {describe_interfaces(chosen)}...')
        browser = mdns.Browser(config.SERVICE_TYPE, chosen)
        try:
            named = sender.find_receivers(browser, context, args.seconds, args.to)
        finally:
            browser.close()
        target = choose(named, args.to)
        address, port, name = target.address, target.port, f'{target.name} ({target.model})'
    say(f'Asking {name} at {address}; accept on the Mac.')
    progress = SendProgress()
    try:
        outcome = sender.deliver(address, port, context, args.name, files,
                                 on_accepted=progress.accepted, on_progress=progress.progress,
                                 ask_seconds=args.ask_timeout)
    except TimeoutError:
        say(f'{name} did not answer in time.')
        return EXIT_FAILED
    except (OSError, http.client.HTTPException) as error:
        say(f'The connection to {name} broke: {sender.describe_attempt(error)}')
        return EXIT_FAILED
    if outcome.result == sender.SENT:
        say(f'Sent {len(files)} file(s) in {outcome.seconds:.1f} s.')
        return 0
    if outcome.result == sender.DECLINED:
        say(f'Declined (HTTP {outcome.status} {outcome.reply.reason}).')
        log.debug('decline reply: headers %s, body %r', outcome.reply.headers, outcome.reply.body[:500])
        return EXIT_DECLINED
    say(f'The receiver refused the upload (HTTP {outcome.status} {outcome.reply.reason}).')
    return EXIT_FAILED


# veer receive

class ConsoleEvents(receiver.Events):
    def __init__(self, prompt):
        self.prompt = prompt
        self._last = 0.0

    def asked(self, offer, sender_left):
        return self.prompt(offer, sender_left)

    def upload_started(self, offer, tid, total):
        say(f'Receiving from {offer.sender_name}...')

    def upload_progress(self, tid, done, total):
        now = time.monotonic()
        if total and now - self._last >= 0.5:
            self._last = now
            print(f'\r  {min(done * 100 // total, 100):3d}%  {done / sender.MIB:.1f} MB',
                  end='', file=sys.stderr, flush=True)

    def stored(self, offer, names, dest):
        if self._last:
            print(file=sys.stderr, flush=True)
            self._last = 0.0
        say(f'Saved in {dest}: {", ".join(names)}')

    def failed(self, offer, reason):
        say(f'Transfer from {offer.sender_name} failed: {reason}')


def valid_name(name):
    if not name or len(name) > config.MAX_NAME_CHARS or any(ord(c) < 32 for c in name):
        raise argparse.ArgumentTypeError(f'1-{config.MAX_NAME_CHARS} characters, no control characters')
    return name


def valid_model(model):
    if not MODEL_RE.match(model):
        raise argparse.ArgumentTypeError('an Apple model identifier such as MacBookPro18,3')
    return model


def valid_percent(text):
    value = int(text)
    if not 1 <= value <= 90:
        raise argparse.ArgumentTypeError('an integer from 1 to 90')
    return value


def cmd_receive(args):
    chosen = interfaces_from(args)
    warn_public_networks(chosen)
    dest = os.path.abspath(os.path.expanduser(args.outdir))
    settings = receiver.Settings(name=args.name, model=args.model, dest=dest, port=args.port,
                                 flags=args.flags, max_receive_percent=args.max_receive_percent,
                                 interfaces=chosen, keys_dir=args.keys,
                                 announce=not args.no_announce)
    events = ConsoleEvents(receiver.ConsolePrompt(args.ask_timeout))
    try:
        running = receiver.start(settings, events)
    except OSError as error:
        raise SystemExit(f'{APP_NAME}: cannot receive: {error}') from None
    say(f'{APP_NAME} is receiving as "{settings.name}" on {describe_interfaces(chosen)}, '
        f'port {running.port}.')
    say(f'Files go to {dest}. Nothing received is opened. Press Ctrl+C to stop.')
    try:
        while running.thread.is_alive():
            running.thread.join(0.5)
    except KeyboardInterrupt:
        say('Stopping.')
    finally:
        running.stop()
    return 0


# veer firewall

def cmd_firewall(args):
    if args.action == 'show':
        return firewall.show()
    if args.action == 'add':
        return firewall.run(firewall.add_commands(args.port), args.dry_run)
    return firewall.run(firewall.remove_commands(), args.dry_run)


def parser():
    top = argparse.ArgumentParser(
        prog='veer', description=f'{APP_NAME}: AirDrop with Macs over the local network.')
    top.add_argument('--version', action='version', version=f'{APP_NAME} {__version__}')
    top.add_argument('-v', '--verbose', action='store_true', help='more detail in the log')
    top.add_argument('--trace', action='store_true',
                     help='protocol-level detail: every record, header and plist')
    top.add_argument('--keys', default=None, help=argparse.SUPPRESS)
    commands = top.add_subparsers(dest='command', required=True)

    def iface(sub):
        sub.add_argument('--iface', action='append', metavar='NAME',
                         help='network interface to use, by name or index (repeatable; '
                              'default: every usable one, see "veer interfaces")')

    sub = commands.add_parser('interfaces', help='list network interfaces')
    sub.set_defaults(run=cmd_interfaces)

    sub = commands.add_parser('discover', help='find Macs announcing AirDrop and ask who they are')
    iface(sub)
    sub.add_argument('--seconds', type=float, default=10, help='how long to look (default 10)')
    sub.add_argument('--address', action='append', metavar='HOST[:PORT]',
                     help='skip multicast DNS and ask this address directly (port 8770 by default)')
    sub.add_argument('--save', metavar='DIR', help='also save each answer, raw, into DIR')
    sub.set_defaults(run=cmd_discover)

    sub = commands.add_parser('send', help='send files to a Mac')
    sub.add_argument('files', nargs='+', help='the files to send')
    sub.add_argument('--to', help="part of the receiver's name, when several answer")
    sub.add_argument('--address', metavar='HOST[:PORT]',
                     help='send to this address directly, without multicast DNS')
    iface(sub)
    sub.add_argument('--name', type=valid_name, default=config.default_device_name(),
                     help='the name the Mac shows for this PC (default: %(default)s)')
    sub.add_argument('--seconds', type=float, default=30, help='how long to look (default 30)')
    sub.add_argument('--ask-timeout', type=float, default=sender.ASK_SECONDS,
                     help='how long to wait for the Mac to accept, in seconds')
    sub.set_defaults(run=cmd_send)

    sub = commands.add_parser('receive', help='receive files from Macs')
    iface(sub)
    sub.add_argument('--name', type=valid_name, default=config.default_device_name(),
                     help='the name Macs show for this PC (default: %(default)s)')
    sub.add_argument('--model', type=valid_model, default=config.DEFAULT_MODEL,
                     help='Apple model identifier; picks the icon Macs draw')
    sub.add_argument('--outdir', default=config.default_download_dir(),
                     help='where received files go (default: %(default)s)')
    sub.add_argument('--port', type=int, default=config.DEFAULT_PORT,
                     help='TCP port to listen on (default: %(default)s)')
    sub.add_argument('--max-receive-percent', type=valid_percent,
                     default=receiver.DEFAULT_MAX_RECEIVE_PERCENT,
                     help='largest transfer, as a percentage of free disk space')
    sub.add_argument('--ask-timeout', type=float, default=receiver.DEFAULT_ASK_TIMEOUT,
                     help='seconds to answer an offer before it is declined')
    sub.add_argument('--flags', type=lambda text: int(text, 0), default=config.DEFAULT_FLAGS,
                     help=argparse.SUPPRESS)
    sub.add_argument('--no-announce', action='store_true', help=argparse.SUPPRESS)
    sub.set_defaults(run=cmd_receive)

    sub = commands.add_parser('firewall', help='Windows Firewall rules for Veer')
    sub.add_argument('action', choices=['show', 'add', 'remove'])
    sub.add_argument('--port', type=int, default=config.DEFAULT_PORT,
                     help='the receive port the TCP rule opens (default: %(default)s)')
    sub.add_argument('--dry-run', action='store_true', help='only print the commands')
    sub.set_defaults(run=cmd_firewall)
    return top


def setup_logging(args):
    level = logging.DEBUG if args.trace else logging.INFO if args.verbose else logging.WARNING
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr,
                        format='%(asctime)s %(levelname)-7s %(name)s: %(message)s')
    logging.getLogger('veer').setLevel(level)


def main(argv=None):
    args = parser().parse_args(argv)
    setup_logging(args)
    try:
        return args.run(args)
    except KeyboardInterrupt:
        return 130
    except identity.ssl.SSLError as error:
        raise SystemExit(f'{APP_NAME}: TLS setup failed: {error}') from None


if __name__ == '__main__':
    sys.exit(main())
