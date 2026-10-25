# SPDX-License-Identifier: MIT
# Adapted from airdrop/mdns.py in winawdl, Copyright (c) 2026 Raphaël Richaud.
"""DNS messages as multicast DNS uses them: building queries and responses,
and parsing what arrives. No sockets here; see mdns.py.

Everything parsed comes from whoever is on the network, so every read is
bounds-checked and a malformed packet raises DNSError, never anything else."""
import ipaddress
import struct
from typing import NamedTuple

TYPE_A, TYPE_PTR, TYPE_TXT, TYPE_AAAA, TYPE_SRV, TYPE_NSEC, TYPE_ANY = 1, 12, 16, 28, 33, 47, 255
TYPE_NAMES = {TYPE_A: 'A', TYPE_PTR: 'PTR', TYPE_TXT: 'TXT', TYPE_AAAA: 'AAAA',
              TYPE_SRV: 'SRV', TYPE_NSEC: 'NSEC', TYPE_ANY: 'ANY'}
CLASS_IN = 1
# In a record: the receiver should replace what it has cached for this name
# and type. In a question: the asker would like a unicast answer (QU).
CACHE_FLUSH = 0x8000
UNICAST_RESPONSE = 0x8000
FLAG_RESPONSE = 0x8000
RESPONSE_FLAGS = 0x8400  # response, authoritative

HEADER_BYTES = 12
RECORD_FIXED_BYTES = 10
POINTER_MASK = 0xC0
# More labels and pointers than any valid name has.
MAX_NAME_STEPS = 128
MAX_LABEL_BYTES = 63
MAX_TXT_STRING_BYTES = 255


class DNSError(ValueError):
    pass


class Question(NamedTuple):
    name: str
    rtype: int
    unicast: bool = False


class Record(NamedTuple):
    """`value` depends on the type: PTR a name, SRV (target, port), A and
    AAAA an address string, TXT a list of byte strings, NSEC the type
    numbers it lists; None for anything else."""
    name: str
    rtype: int
    ttl: int
    value: object
    cache_flush: bool = False


class Message(NamedTuple):
    id: int
    flags: int
    questions: list
    records: list  # answers, authority and additional, in that order

    @property
    def is_response(self):
        return bool(self.flags & FLAG_RESPONSE)


def encode_name(name):
    out = b''
    for label in name.rstrip('.').split('.'):
        raw = label.encode('utf-8')
        if not 0 < len(raw) <= MAX_LABEL_BYTES:
            raise ValueError(f'invalid DNS label {label!r}')
        out += bytes([len(raw)]) + raw
    return out + b'\0'


def _byte(packet, offset):
    if offset >= len(packet):
        raise DNSError('name runs past the end of the packet')
    return packet[offset]


def decode_name(packet, offset):
    """The name at `offset` and the offset just past it, following
    compression pointers."""
    labels = []
    end = None
    for _ in range(MAX_NAME_STEPS):
        length = _byte(packet, offset)
        if length & POINTER_MASK == POINTER_MASK:
            if end is None:
                end = offset + 2
            offset = (length & ~POINTER_MASK) << 8 | _byte(packet, offset + 1)
        elif length & POINTER_MASK:
            raise DNSError(f'reserved label type {length:#x}')
        elif length == 0:
            return '.'.join(labels), offset + 1 if end is None else end
        else:
            start = offset + 1
            if start + length > len(packet):
                raise DNSError('label runs past the end of the packet')
            labels.append(packet[start:start + length].decode('utf-8', 'replace'))
            offset = start + length
    raise DNSError('name does not terminate')


def _unpack(fmt, packet, offset):
    try:
        return struct.unpack_from(fmt, packet, offset)
    except struct.error:
        raise DNSError('packet is truncated') from None


def parse_txt(rdata):
    """The strings of a TXT record's data."""
    strings = []
    offset = 0
    while offset < len(rdata):
        length = rdata[offset]
        offset += 1
        if offset + length > len(rdata):
            raise DNSError('TXT string runs past its record')
        strings.append(bytes(rdata[offset:offset + length]))
        offset += length
    return strings


def txt_dict(strings):
    """TXT strings as key -> value (bytes), the first of each key winning
    (RFC 6763 6.4). A key with no "=" maps to None."""
    found = {}
    for string in strings:
        key, sep, value = string.partition(b'=')
        name = key.decode('ascii', 'replace').lower()
        if name and name not in found:
            found[name] = value if sep else None
    return found


def _nsec_types(rdata, offset_after_name):
    types = []
    offset = offset_after_name
    while offset + 2 <= len(rdata):
        window, length = rdata[offset], rdata[offset + 1]
        bitmap = rdata[offset + 2:offset + 2 + length]
        for index, byte in enumerate(bitmap):
            for bit in range(8):
                if byte & (0x80 >> bit):
                    types.append(window * 256 + index * 8 + bit)
        offset += 2 + length
    return types


def _record_value(packet, rtype, start, end):
    if rtype == TYPE_PTR:
        return decode_name(packet, start)[0]
    if rtype == TYPE_SRV:
        if end - start < 7:
            raise DNSError('SRV record too short')
        port = _unpack('!H', packet, start + 4)[0]
        return decode_name(packet, start + 6)[0], port
    if rtype == TYPE_A and end - start == 4:
        return str(ipaddress.IPv4Address(packet[start:end]))
    if rtype == TYPE_AAAA and end - start == 16:
        return str(ipaddress.IPv6Address(packet[start:end]))
    if rtype == TYPE_TXT:
        return parse_txt(packet[start:end])
    if rtype == TYPE_NSEC:
        rdata = packet[:end]
        return _nsec_types(rdata, decode_name(rdata, start)[1])
    return None


def parse(packet):
    """The whole message, or DNSError for anything malformed."""
    msg_id, flags, qdcount, ancount, nscount, arcount = _unpack('!HHHHHH', packet, 0)
    offset = HEADER_BYTES
    questions = []
    for _ in range(qdcount):
        name, offset = decode_name(packet, offset)
        rtype, rclass = _unpack('!HH', packet, offset)
        offset += 4
        questions.append(Question(name, rtype, bool(rclass & UNICAST_RESPONSE)))
    records = []
    for _ in range(ancount + nscount + arcount):
        name, offset = decode_name(packet, offset)
        rtype, rclass, ttl, length = _unpack('!HHIH', packet, offset)
        offset += RECORD_FIXED_BYTES
        if offset + length > len(packet):
            raise DNSError('record data runs past the end of the packet')
        value = _record_value(packet, rtype, offset, offset + length)
        records.append(Record(name, rtype, ttl, value, bool(rclass & CACHE_FLUSH)))
        offset += length
    return Message(msg_id, flags, questions, records)


def try_parse(packet):
    """parse(), or None for a packet that is not a valid DNS message."""
    try:
        return parse(packet)
    except (DNSError, ValueError):
        return None


# Building.

def encode_txt(strings):
    """TXT record data from strings such as 'flags=1019'. An empty TXT
    still holds one empty string (RFC 6763 6.1)."""
    out = b''
    for string in strings or ['']:
        raw = string.encode('utf-8') if isinstance(string, str) else string
        if len(raw) > MAX_TXT_STRING_BYTES:
            raise ValueError('TXT string longer than 255 bytes')
        out += bytes([len(raw)]) + raw
    return out


def nsec_bitmap(types):
    """An NSEC type bitmap for types below 256 (window 0 only)."""
    types = sorted(set(types))
    if not types or types[-1] > 255:
        raise ValueError('only window 0 is supported')
    bitmap = bytearray(types[-1] // 8 + 1)
    for rtype in types:
        bitmap[rtype // 8] |= 0x80 >> (rtype % 8)
    return bytes([0, len(bitmap)]) + bytes(bitmap)


def encode_record(name, rtype, ttl, rdata, cache_flush=False):
    rclass = CLASS_IN | (CACHE_FLUSH if cache_flush else 0)
    return encode_name(name) + struct.pack('!HHIH', rtype, rclass, ttl, len(rdata)) + rdata


def ptr_rdata(target):
    return encode_name(target)


def srv_rdata(target, port, priority=0, weight=0):
    return struct.pack('!HHH', priority, weight, port) + encode_name(target)


def address_rdata(address):
    return ipaddress.ip_address(address).packed


def build_query(questions, msg_id=0):
    """A query for Question tuples."""
    asked = b''.join(
        encode_name(q.name) + struct.pack(
            '!HH', q.rtype, CLASS_IN | (UNICAST_RESPONSE if q.unicast else 0))
        for q in questions)
    return struct.pack('!HHHHHH', msg_id, 0, len(questions), 0, 0, 0) + asked


def build_response(answers, additional=(), msg_id=0, questions=()):
    """A response from already-encoded records. `questions` are echoed only
    for legacy unicast replies, which need them (RFC 6762 6.7)."""
    echoed = b''.join(encode_name(q.name) + struct.pack('!HH', q.rtype, CLASS_IN)
                      for q in questions)
    header = struct.pack('!HHHHHH', msg_id, RESPONSE_FLAGS, len(questions),
                         len(answers), 0, len(additional))
    return header + echoed + b''.join(answers) + b''.join(additional)
