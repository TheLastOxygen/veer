# SPDX-License-Identifier: MIT
"""The network interfaces Veer can use: their names, indexes and addresses.

On Windows this asks GetAdaptersAddresses, which gives the names shown in
Settings ("Wi-Fi", "Ethernet"), the index a scoped IPv6 address needs, and
each address's prefix length, used to tell which interface an IPv4 packet
came in on. Elsewhere a rough stand-in is used, enough for development."""
import ctypes
import ipaddress
import socket
import sys
from typing import NamedTuple

IF_TYPE_ETHERNET = 6
IF_TYPE_LOOPBACK = 24
IF_TYPE_WIFI = 71
IF_TYPE_TUNNEL = 131
IF_OPER_STATUS_UP = 1
KINDS = {IF_TYPE_ETHERNET: 'ethernet', IF_TYPE_WIFI: 'wi-fi', IF_TYPE_LOOPBACK: 'loopback',
         IF_TYPE_TUNNEL: 'tunnel'}

AF_INET_WIN = 2
AF_INET6_WIN = 23
GAA_FLAG_SKIP_ANYCAST = 0x2
GAA_FLAG_SKIP_MULTICAST = 0x4
GAA_FLAG_SKIP_DNS_SERVER = 0x8
ERROR_BUFFER_OVERFLOW = 111
NO_ERROR = 0


class Interface(NamedTuple):
    name: str
    description: str
    index: int        # the IPv4 interface index
    ipv6_index: int   # the IPv6 one, which a scoped address names
    kind: str
    ipv4: tuple       # of ipaddress.IPv4Interface
    ipv6: tuple       # of ipaddress.IPv6Interface

    @property
    def is_loopback(self):
        return self.kind == 'loopback'

    @property
    def ipv4_address(self):
        return str(self.ipv4[0].ip) if self.ipv4 else None

    @property
    def link_local(self):
        """The IPv6 link-local address, without its scope, or None."""
        for address in self.ipv6:
            if address.ip.is_link_local:
                return str(address.ip)
        return None

    def owns_peer(self, address):
        """Whether `address` (no scope) is on one of this interface's IPv4
        subnets. IPv6 peers are matched by scope id instead."""
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return isinstance(ip, ipaddress.IPv4Address) and any(
            ip in net.network for net in self.ipv4)

    def summary(self):
        addresses = [str(a.ip) for a in self.ipv4] + [str(a.ip) for a in self.ipv6]
        return f'{self.name} [{self.kind}, index {self.index}]: {", ".join(addresses) or "no address"}'


class _SocketAddress(ctypes.Structure):
    _fields_ = [('lpSockaddr', ctypes.c_void_p), ('iSockaddrLength', ctypes.c_int)]


class _UnicastAddress(ctypes.Structure):
    pass


_UnicastAddress._fields_ = [
    ('Length', ctypes.c_ulong), ('Flags', ctypes.c_ulong),
    ('Next', ctypes.POINTER(_UnicastAddress)),
    ('Address', _SocketAddress),
    ('PrefixOrigin', ctypes.c_int), ('SuffixOrigin', ctypes.c_int), ('DadState', ctypes.c_int),
    ('ValidLifetime', ctypes.c_ulong), ('PreferredLifetime', ctypes.c_ulong),
    ('LeaseLifetime', ctypes.c_ulong),
    ('OnLinkPrefixLength', ctypes.c_uint8),
]


class _AdapterAddresses(ctypes.Structure):
    """IP_ADAPTER_ADDRESSES_LH up to Ipv6IfIndex; nothing after it is read,
    and the structures are only ever read from the buffer Windows fills."""


_AdapterAddresses._fields_ = [
    ('Length', ctypes.c_ulong), ('IfIndex', ctypes.c_ulong),
    ('Next', ctypes.POINTER(_AdapterAddresses)),
    ('AdapterName', ctypes.c_char_p),
    ('FirstUnicastAddress', ctypes.POINTER(_UnicastAddress)),
    ('FirstAnycastAddress', ctypes.c_void_p),
    ('FirstMulticastAddress', ctypes.c_void_p),
    ('FirstDnsServerAddress', ctypes.c_void_p),
    ('DnsSuffix', ctypes.c_wchar_p),
    ('Description', ctypes.c_wchar_p),
    ('FriendlyName', ctypes.c_wchar_p),
    ('PhysicalAddress', ctypes.c_ubyte * 8),
    ('PhysicalAddressLength', ctypes.c_ulong),
    ('Flags', ctypes.c_ulong),
    ('Mtu', ctypes.c_ulong),
    ('IfType', ctypes.c_ulong),
    ('OperStatus', ctypes.c_int),
    ('Ipv6IfIndex', ctypes.c_ulong),
]


def _sockaddr(address):
    raw = ctypes.string_at(address.lpSockaddr, address.iSockaddrLength)
    family = int.from_bytes(raw[0:2], 'little')
    if family == AF_INET_WIN and len(raw) >= 8:
        return ipaddress.IPv4Address(raw[4:8])
    if family == AF_INET6_WIN and len(raw) >= 24:
        return ipaddress.IPv6Address(raw[8:24])
    return None


def _windows_interfaces():
    iphlpapi = ctypes.WinDLL('iphlpapi')
    flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER
    size = ctypes.c_ulong(16 * 1024)
    for _ in range(4):
        buffer = ctypes.create_string_buffer(size.value)
        result = iphlpapi.GetAdaptersAddresses(0, flags, None, buffer, ctypes.byref(size))
        if result != ERROR_BUFFER_OVERFLOW:
            break
    if result != NO_ERROR:
        raise OSError(f'GetAdaptersAddresses failed with error {result}')
    found = []
    adapter = ctypes.cast(buffer, ctypes.POINTER(_AdapterAddresses))
    while adapter:
        entry = adapter.contents
        ipv4, ipv6 = [], []
        unicast = entry.FirstUnicastAddress
        while unicast:
            item = unicast.contents
            ip = _sockaddr(item.Address)
            if ip is not None:
                interface = ipaddress.ip_interface(f'{ip}/{item.OnLinkPrefixLength}')
                (ipv4 if ip.version == 4 else ipv6).append(interface)
            unicast = item.Next
        if entry.OperStatus == IF_OPER_STATUS_UP:
            found.append(Interface(
                name=entry.FriendlyName or '', description=entry.Description or '',
                index=entry.IfIndex, ipv6_index=entry.Ipv6IfIndex,
                kind=KINDS.get(entry.IfType, 'other'),
                ipv4=tuple(ipv4), ipv6=tuple(ipv6)))
        adapter = entry.Next
    return found


def _fallback_interfaces():
    """Outside Windows: the address the default route leaves from, plus the
    loopback interface. Enough to develop and run the tests."""
    found = [Interface('loopback', 'loopback', 1, 1, 'loopback',
                       (ipaddress.IPv4Interface('127.0.0.1/8'),),
                       (ipaddress.IPv6Interface('::1/128'),))]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            probe.connect(('224.0.0.251', 5353))
            address = probe.getsockname()[0]
        except OSError:
            return found
    try:
        index = socket.if_nameindex()[0][0]
    except (OSError, IndexError, AttributeError):
        index = 0
    found.append(Interface('default', 'default route', index, index, 'other',
                           (ipaddress.IPv4Interface(f'{address}/24'),), ()))
    return found


def all_interfaces():
    """Every interface that is up, loopback included."""
    if sys.platform == 'win32':
        return _windows_interfaces()
    return _fallback_interfaces()


def usable(interface):
    """Whether Veer uses an interface unless told otherwise: up, not
    loopback, not a tunnel, and with an address AirDrop can reach."""
    return (not interface.is_loopback and interface.kind != 'tunnel'
            and bool(interface.ipv4 or interface.link_local))


def select(wanted=None, interfaces=None):
    """The interfaces named in `wanted` (friendly names, case-insensitive, or
    index numbers), or every usable one when `wanted` is empty. Naming one
    explicitly allows loopback, which the tests use."""
    interfaces = all_interfaces() if interfaces is None else interfaces
    if not wanted:
        return [i for i in interfaces if usable(i)]
    chosen = []
    for want in wanted:
        matches = [i for i in interfaces
                   if i.name.lower() == want.lower() or str(i.index) == want]
        if not matches:
            names = ', '.join(repr(i.name) for i in interfaces)
            raise LookupError(f'no interface named {want!r}; there are: {names}')
        chosen.extend(m for m in matches if m not in chosen)
    return chosen


def loopback(interfaces=None):
    interfaces = all_interfaces() if interfaces is None else interfaces
    for interface in interfaces:
        if interface.is_loopback:
            return interface
    return None
