# SPDX-License-Identifier: MIT
# Adapted from airdrop/mdns.py in winawdl, Copyright (c) 2026 Raphaël Richaud.
"""Multicast DNS on the LAN: announcing one DNS-SD service and browsing for
the instances others announce, over IPv4 and IPv6, on several interfaces.

Windows' own resolver holds UDP 5353 too. Every socket here binds it with
SO_REUSEADDR, and multicast is delivered to each of them; browsing also asks
from an ephemeral port, whose answers come back by unicast (RFC 6762 6.7),
so they reach us whatever else shares 5353."""
import logging
import secrets
import select
import socket
import struct
import threading
import time
from typing import NamedTuple

from . import dns

log = logging.getLogger('veer.mdns')

GROUP4 = '224.0.0.251'
GROUP6 = 'ff02::fb'
PORT = 5353
MAX_PACKET = 9000
SERVICES_META = '_services._dns-sd._udp.local'

TTL_SERVICE = 4500
TTL_HOST = 120
# Legacy unicast answers must not be cached for longer (RFC 6762 6.7).
TTL_LEGACY_MAX = 10
# Announced this many times at start, a second apart (RFC 6762 8.3), then
# again every ANNOUNCE_PERIOD_S so a peer that missed us still learns of us.
STARTUP_ANNOUNCEMENTS = 3
ANNOUNCE_PERIOD_S = 60.0
# Peers repeat a query several times within a few milliseconds.
MIN_REPLY_GAP_S = 0.25
QUERY_PERIOD_S = 1.0


class Endpoint(NamedTuple):
    """One socket family's view of an interface."""
    interface: object  # netif.Interface
    family: int


def _set_v4_interface(sock, interface):
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                    socket.inet_aton(interface.ipv4_address))


def _set_v6_interface(sock, interface):
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, interface.ipv6_index)


def _open_v4(port, interfaces, join):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', port))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    except OSError:
        sock.close()
        raise
    joined = []
    for interface in interfaces:
        if not interface.ipv4_address:
            continue
        if join:
            membership = socket.inet_aton(GROUP4) + socket.inet_aton(interface.ipv4_address)
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
            except OSError as error:
                log.warning('cannot join %s on %s: %s', GROUP4, interface.name, error)
                continue
        joined.append(interface)
    return sock, joined


def _open_v6(port, interfaces, join):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind(('::', port))
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 1)
    except OSError:
        sock.close()
        raise
    joined = []
    for interface in interfaces:
        if not interface.link_local:
            continue
        if join:
            membership = socket.inet_pton(socket.AF_INET6, GROUP6) + struct.pack(
                '@I', interface.ipv6_index)
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, membership)
            except OSError as error:
                log.warning('cannot join %s on %s: %s', GROUP6, interface.name, error)
                continue
        joined.append(interface)
    return sock, joined


class Transport:
    """A pair of sockets, IPv4 and IPv6, for multicast DNS on some interfaces.
    `port` is 5353 for the shared multicast sockets, 0 for the one-shot
    sockets a browser asks from."""

    def __init__(self, interfaces, port=PORT):
        self.interfaces = list(interfaces)
        self.port = port
        join = port == PORT
        self._lock = threading.Lock()
        self.v4 = self.v6 = None
        self.v4_interfaces = self.v6_interfaces = []
        try:
            self.v4, self.v4_interfaces = _open_v4(port, self.interfaces, join)
        except OSError as error:
            log.warning('no IPv4 multicast DNS: %s', error)
        try:
            self.v6, self.v6_interfaces = _open_v6(port, self.interfaces, join)
        except OSError as error:
            log.warning('no IPv6 multicast DNS: %s', error)
        if not self.v4_interfaces and not self.v6_interfaces:
            self.close()
            raise OSError('multicast DNS is not available on any of the interfaces')

    def close(self):
        for sock in (self.v4, self.v6):
            if sock:
                sock.close()

    def sockets(self):
        return [sock for sock in (self.v4, self.v6) if sock]

    def multicast(self, packet, interface):
        """Send `packet` to the mDNS group on `interface`, over each family the
        interface has."""
        with self._lock:
            if self.v4 and interface in self.v4_interfaces:
                try:
                    _set_v4_interface(self.v4, interface)
                    self.v4.sendto(packet, (GROUP4, PORT))
                except OSError as error:
                    log.warning('IPv4 send on %s failed: %s', interface.name, error)
            if self.v6 and interface in self.v6_interfaces:
                try:
                    _set_v6_interface(self.v6, interface)
                    self.v6.sendto(packet, (GROUP6, PORT, 0, interface.ipv6_index))
                except OSError as error:
                    log.warning('IPv6 send on %s failed: %s', interface.name, error)

    def unicast(self, packet, source):
        """Answer `source`, a recvfrom address, directly."""
        sock = self.v6 if len(source) == 4 else self.v4
        try:
            sock.sendto(packet, source)
        except OSError as error:
            log.warning('unicast reply to %s failed: %s', source[0], error)

    def interface_of(self, source):
        """The interface a packet from `source` arrived on, or None."""
        if len(source) == 4:  # IPv6: (address, port, flowinfo, scope)
            for interface in self.v6_interfaces:
                if interface.ipv6_index == source[3]:
                    return interface
            return None
        for interface in self.v4_interfaces:
            if source[0] == interface.ipv4_address or interface.owns_peer(source[0]):
                return interface
        return None


def receive(transports, timeout):
    """Wait up to `timeout` for one packet on any of the transports' sockets.
    Returns (packet, source, transport) or None."""
    owners = {sock: transport for transport in transports for sock in transport.sockets()}
    if not owners:
        time.sleep(timeout)
        return None
    try:
        ready, _, _ = select.select(list(owners), [], [], timeout)
    except (OSError, ValueError):
        return None
    for sock in ready:
        try:
            packet, source = sock.recvfrom(MAX_PACKET)
        except (ConnectionResetError, OSError):
            # Windows reports an ICMP port-unreachable from an earlier
            # unicast send as an error on the next receive.
            continue
        return packet, source, owners[sock]
    return None


def bare(address):
    """An address without its %scope."""
    return address.split('%')[0]


# Announcing.

def new_service_id():
    """12 hex digits, the shape of every AirDrop instance name."""
    return secrets.token_hex(6)


class Service:
    """The records of one DNS-SD instance; the addresses are those of the
    interface each response goes out on."""

    def __init__(self, service_type, instance, port, text, host=None):
        self.type_name = service_type
        self.instance = instance
        self.instance_name = f'{instance}.{service_type}'
        self.host_name = host or f'veer-{instance}.local'
        self.port = port
        self.text = list(text)

    def owns(self, name):
        return name.lower() in {self.type_name.lower(), self.instance_name.lower(),
                                self.host_name.lower(), SERVICES_META}

    def records(self, interface, alive=True, legacy=False):
        """Every record, encoded, as seen on `interface`."""
        service_ttl = TTL_SERVICE if alive else 0
        host_ttl = TTL_HOST if alive else 0
        if legacy:
            service_ttl = min(service_ttl, TTL_LEGACY_MAX)
            host_ttl = min(host_ttl, TTL_LEGACY_MAX)
        flush = not legacy
        records = [
            dns.encode_record(self.type_name, dns.TYPE_PTR, service_ttl,
                              dns.ptr_rdata(self.instance_name)),
            dns.encode_record(self.instance_name, dns.TYPE_SRV, host_ttl,
                              dns.srv_rdata(self.host_name, self.port), flush),
            dns.encode_record(self.instance_name, dns.TYPE_TXT, service_ttl,
                              dns.encode_txt(self.text), flush),
        ]
        types = [dns.TYPE_NSEC]
        for address in interface.ipv4:
            records.append(dns.encode_record(self.host_name, dns.TYPE_A, host_ttl,
                                             dns.address_rdata(address.ip), flush))
            types.append(dns.TYPE_A)
        if interface.link_local:
            records.append(dns.encode_record(self.host_name, dns.TYPE_AAAA, host_ttl,
                                             dns.address_rdata(interface.link_local), flush))
            types.append(dns.TYPE_AAAA)
        # Says which types the host has, so a peer stops waiting for the
        # others (omdrop found Apple devices wait for a missing A record).
        records.append(dns.encode_record(
            self.host_name, dns.TYPE_NSEC, host_ttl,
            dns.encode_name(self.host_name) + dns.nsec_bitmap(types), flush))
        if not legacy:
            records.append(dns.encode_record(SERVICES_META, dns.TYPE_PTR, service_ttl,
                                             dns.ptr_rdata(self.type_name)))
        return records

    def response(self, interface, alive=True):
        return dns.build_response(self.records(interface, alive))

    def legacy_response(self, interface, query):
        """The unicast answer to a query from a port other than 5353, which
        echoes its id and questions."""
        asked = [q for q in query.questions if self.owns(q.name)]
        return dns.build_response(self.records(interface, legacy=True),
                                  msg_id=query.id, questions=asked)


class Responder:
    """Keeps a Service announced, and answers queries for it, on some
    interfaces until stopped."""

    def __init__(self, service, interfaces):
        self.service = service
        self.transport = Transport(interfaces)
        self.interfaces = sorted(set(self.transport.v4_interfaces) | set(self.transport.v6_interfaces),
                                 key=lambda i: i.index)
        self._stopping = threading.Event()
        self._thread = threading.Thread(target=self._run, name='veer-mdns', daemon=True)
        self._last_reply = {}
        self.queries_answered = 0

    def start(self):
        self._thread.start()

    def stop(self):
        self._stopping.set()
        self._thread.join()
        for interface in self.interfaces:
            self.transport.multicast(self.service.response(interface, alive=False), interface)
        self.transport.close()

    def announce(self):
        for interface in self.interfaces:
            self.transport.multicast(self.service.response(interface), interface)

    def handle(self, packet, source):
        """Answer `packet` if it is a query for our names."""
        message = dns.try_parse(packet)
        if message is None or message.is_response:
            return
        asked = [q for q in message.questions if self.service.owns(q.name)]
        if not asked:
            return
        interface = self.transport.interface_of(source)
        if interface is None:
            return
        log.debug('query from %s on %s for %s', bare(source[0]), interface.name,
                  ', '.join(f'{q.name} {dns.TYPE_NAMES.get(q.rtype, q.rtype)}' for q in asked))
        self.queries_answered += 1
        if source[1] != PORT:
            self.transport.unicast(self.service.legacy_response(interface, message), source)
            return
        now = time.monotonic()
        if now - self._last_reply.get(interface.index, 0) < MIN_REPLY_GAP_S:
            return
        self._last_reply[interface.index] = now
        self.transport.multicast(self.service.response(interface), interface)

    def _run(self):
        schedule = [time.monotonic() + i for i in range(STARTUP_ANNOUNCEMENTS)]
        while not self._stopping.is_set():
            now = time.monotonic()
            if schedule and now >= schedule[0]:
                schedule.pop(0)
                self.announce()
                if not schedule:
                    schedule.append(now + ANNOUNCE_PERIOD_S)
            wait = max(0.0, min(0.5, schedule[0] - now)) if schedule else 0.5
            got = receive([self.transport], wait)
            if got:
                self.handle(got[0], got[1])


# Browsing.

class Peer(NamedTuple):
    """One instance that can be reached."""
    instance: str            # e.g. 0e9d036c5823._airdrop._tcp.local
    interface: object        # netif.Interface it was heard on
    host: str
    port: int
    addresses: tuple         # connectable addresses, IPv4 first; IPv6 ones scoped
    txt: dict                # key -> bytes or None
    txt_raw: tuple           # the TXT strings as sent
    source: str              # where the answer came from

    @property
    def instance_id(self):
        return self.instance.split('.', 1)[0]

    @property
    def flags(self):
        try:
            return int((self.txt.get('flags') or b'').decode('ascii'), 0)
        except ValueError:
            return None


class _Heard:
    def __init__(self):
        self.srv = None
        self.txt = None
        self.interface = None
        self.source = None
        self.last = 0.0


class Browser:
    """Asks some interfaces for one service type and keeps what answers.
    Call poll() repeatedly; peers() says what is known so far."""

    def __init__(self, service_type, interfaces):
        self.type_name = service_type.lower()
        self.multicast = Transport(interfaces)
        self.interfaces = sorted(set(self.multicast.v4_interfaces) | set(self.multicast.v6_interfaces),
                                 key=lambda i: i.index)
        try:
            self.oneshot = Transport(self.interfaces, port=0)
        except OSError:
            self.oneshot = None
        self._instances = {}
        self._addresses = {}  # (host, interface index) -> set of addresses
        self._last_asked = 0.0
        self.packets = 0      # responses heard, of any service
        self.on_record = None  # optional callback(record, source, interface)

    def close(self):
        self.multicast.close()
        if self.oneshot:
            self.oneshot.close()

    def _questions(self):
        missing = [name for name, heard in self._instances.items()
                   if heard.srv is None or heard.txt is None]
        questions = [dns.Question(self.type_name, dns.TYPE_PTR)]
        questions += [dns.Question(name, dns.TYPE_ANY) for name in missing]
        return questions

    def ask(self):
        query = dns.build_query(self._questions())
        for interface in self.interfaces:
            self.multicast.multicast(query, interface)
            if self.oneshot:
                self.oneshot.multicast(query, interface)

    def poll(self, timeout=0.25):
        """Ask if it is time to, and take in what arrives within `timeout`."""
        if time.monotonic() - self._last_asked >= QUERY_PERIOD_S:
            self._last_asked = time.monotonic()
            self.ask()
        transports = [self.multicast] + ([self.oneshot] if self.oneshot else [])
        deadline = time.monotonic() + timeout
        while True:
            got = receive(transports, max(0.0, deadline - time.monotonic()))
            if got:
                self.feed(*got)
            if time.monotonic() >= deadline:
                return self.peers()

    def feed(self, packet, source, transport):
        message = dns.try_parse(packet)
        if message is None or not message.is_response:
            return
        interface = transport.interface_of(source)
        if interface is None:
            return
        self.packets += 1
        for record in message.records:
            self._take(record, source, interface)

    def _take(self, record, source, interface):
        name = record.name.lower()
        if self.on_record and (name == self.type_name or name.endswith('.' + self.type_name)):
            self.on_record(record, source, interface)
        if record.rtype == dns.TYPE_PTR and name == self.type_name:
            instance = record.value.lower()
            if record.ttl == 0:
                self._instances.pop(instance, None)
                return
            heard = self._instances.setdefault(instance, _Heard())
            heard.interface, heard.source, heard.last = interface, bare(source[0]), time.monotonic()
        elif record.rtype in (dns.TYPE_SRV, dns.TYPE_TXT) and name.endswith('.' + self.type_name):
            if record.ttl == 0:  # part of a goodbye
                self._instances.pop(name, None)
                return
            heard = self._instances.setdefault(name, _Heard())
            heard.interface = heard.interface or interface
            heard.source = heard.source or bare(source[0])
            if record.rtype == dns.TYPE_SRV:
                heard.srv = (record.value[0].lower(), record.value[1])
            else:
                heard.txt = tuple(record.value)
        elif record.rtype in (dns.TYPE_A, dns.TYPE_AAAA):
            self._addresses.setdefault((name, interface.index), set()).add(record.value)

    def peers(self):
        """Every instance whose service record is known, with its addresses."""
        found = []
        for instance, heard in sorted(self._instances.items()):
            if heard.srv is None:
                continue
            host, port = heard.srv
            known = self._addresses.get((host, heard.interface.index), set())
            v4 = sorted(a for a in known if ':' not in a)
            v6 = sorted(a for a in known if ':' in a)
            addresses = v4 + [f'{a}%{heard.interface.ipv6_index}' if a.lower().startswith('fe80')
                              else a for a in v6]
            if not addresses and heard.source:
                scoped = (f'{heard.source}%{heard.interface.ipv6_index}'
                          if heard.source.lower().startswith('fe80') else heard.source)
                addresses = [scoped]
            txt = heard.txt or ()
            found.append(Peer(instance, heard.interface, host, port, tuple(addresses),
                              dns.txt_dict(txt), txt, heard.source or ''))
        return found
