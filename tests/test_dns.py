# SPDX-License-Identifier: MIT
import ipaddress
import struct
import unittest

from veer import dns, mdns, netif

LAN = netif.Interface('Ethernet', 'test', 11, 11, 'ethernet',
                      (ipaddress.IPv4Interface('192.168.1.10/24'),),
                      (ipaddress.IPv6Interface('fe80::1/64'),))


class NameTest(unittest.TestCase):
    def test_round_trip(self):
        encoded = dns.encode_name('abc._airdrop._tcp.local')
        self.assertEqual(dns.decode_name(encoded, 0), ('abc._airdrop._tcp.local', len(encoded)))

    def test_compression_pointer(self):
        packet = dns.encode_name('_tcp.local') + b'\x03abc\xc0\x00'
        self.assertEqual(dns.decode_name(packet, 12)[0], 'abc._tcp.local')

    def test_pointer_loop_is_rejected(self):
        with self.assertRaises(dns.DNSError):
            dns.decode_name(b'\xc0\x00', 0)

    def test_truncated_label_is_rejected(self):
        with self.assertRaises(dns.DNSError):
            dns.decode_name(b'\x05ab', 0)

    def test_overlong_label_is_refused_when_encoding(self):
        with self.assertRaises(ValueError):
            dns.encode_name('a' * 64 + '.local')


class MessageTest(unittest.TestCase):
    def test_query_round_trip(self):
        packet = dns.build_query([dns.Question('_airdrop._tcp.local', dns.TYPE_PTR, True)], 7)
        message = dns.parse(packet)
        self.assertFalse(message.is_response)
        self.assertEqual(message.id, 7)
        self.assertEqual(message.questions, [dns.Question('_airdrop._tcp.local', dns.TYPE_PTR, True)])

    def test_garbage_never_raises_anything_but_none(self):
        for packet in (b'', b'\x00' * 5, b'\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00\xff',
                       bytes(range(256))):
            self.assertIsNone(dns.try_parse(packet))

    def test_record_length_past_end_is_rejected(self):
        record = dns.encode_name('x.local') + struct.pack('!HHIH', dns.TYPE_A, 1, 120, 50) + b'\x01\x02'
        packet = struct.pack('!HHHHHH', 0, dns.RESPONSE_FLAGS, 0, 1, 0, 0) + record
        self.assertIsNone(dns.try_parse(packet))

    def test_txt(self):
        rdata = dns.encode_txt(['flags=1019', 'Flags=1', 'novalue', ''])
        strings = dns.parse_txt(rdata)
        self.assertEqual(strings, [b'flags=1019', b'Flags=1', b'novalue', b''])
        self.assertEqual(dns.txt_dict(strings), {'flags': b'1019', 'novalue': None})

    def test_empty_txt_holds_one_empty_string(self):
        self.assertEqual(dns.encode_txt([]), b'\x00')

    def test_nsec_bitmap(self):
        self.assertEqual(dns.nsec_bitmap([dns.TYPE_AAAA, dns.TYPE_NSEC]),
                         bytes([0, 6, 0, 0, 0, 0x08, 0, 0x01]))


class ServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = mdns.Service('_airdrop._tcp.local', '0123456789ab', 8771, ['flags=1019'])

    def test_response_carries_every_record(self):
        message = dns.parse(self.service.response(LAN))
        self.assertTrue(message.is_response)
        by_type = {}
        for record in message.records:
            by_type.setdefault(record.rtype, []).append(record)
        self.assertEqual(by_type[dns.TYPE_SRV][0].value, ('veer-0123456789ab.local', 8771))
        self.assertEqual(by_type[dns.TYPE_TXT][0].value, [b'flags=1019'])
        self.assertEqual(by_type[dns.TYPE_A][0].value, '192.168.1.10')
        self.assertEqual(by_type[dns.TYPE_AAAA][0].value, 'fe80::1')
        self.assertEqual(sorted(by_type[dns.TYPE_NSEC][0].value),
                         [dns.TYPE_A, dns.TYPE_AAAA, dns.TYPE_NSEC])
        self.assertTrue(by_type[dns.TYPE_SRV][0].cache_flush)
        self.assertFalse(by_type[dns.TYPE_PTR][0].cache_flush)

    def test_goodbye_has_zero_ttls(self):
        message = dns.parse(self.service.response(LAN, alive=False))
        self.assertTrue(all(record.ttl == 0 for record in message.records))

    def test_legacy_reply_echoes_id_and_question_with_short_ttls(self):
        query = dns.parse(dns.build_query([dns.Question('_airdrop._tcp.local', dns.TYPE_PTR)], 0x1234))
        message = dns.parse(self.service.legacy_response(LAN, query))
        self.assertEqual(message.id, 0x1234)
        self.assertEqual([q.name for q in message.questions], ['_airdrop._tcp.local'])
        self.assertTrue(all(record.ttl <= mdns.TTL_LEGACY_MAX for record in message.records))
        self.assertFalse(any(record.cache_flush for record in message.records))

    def test_owns_its_names_case_insensitively(self):
        self.assertTrue(self.service.owns('_AirDrop._tcp.local'))
        self.assertTrue(self.service.owns('0123456789AB._airdrop._tcp.local'))
        self.assertTrue(self.service.owns('veer-0123456789ab.local'))
        self.assertFalse(self.service.owns('_http._tcp.local'))


class FakeTransport:
    def __init__(self):
        self.v4_interfaces = [LAN]
        self.v6_interfaces = [LAN]

    interface_of = mdns.Transport.interface_of


class BrowserFeedTest(unittest.TestCase):
    def browser(self):
        browser = mdns.Browser.__new__(mdns.Browser)
        browser.type_name = '_airdrop._tcp.local'
        browser._instances, browser._addresses = {}, {}
        browser.packets = 0
        browser.on_record = None
        return browser

    def test_a_response_becomes_a_peer(self):
        service = mdns.Service('_airdrop._tcp.local', 'aabbccddeeff', 8770, ['flags=1019'],
                               host='mac.local')
        browser = self.browser()
        browser.feed(service.response(LAN), ('192.168.1.20', 5353), FakeTransport())
        [peer] = browser.peers()
        self.assertEqual(peer.instance_id, 'aabbccddeeff')
        self.assertEqual(peer.port, 8770)
        self.assertEqual(peer.flags, 1019)
        # The record's addresses, not the sender's: IPv4 first, IPv6 scoped.
        self.assertEqual(peer.addresses, ('192.168.1.10', 'fe80::1%11'))

    def test_a_packet_from_another_subnet_is_ignored(self):
        service = mdns.Service('_airdrop._tcp.local', 'aabbccddeeff', 8770, [])
        browser = self.browser()
        browser.feed(service.response(LAN), ('10.0.0.5', 5353), FakeTransport())
        self.assertEqual(browser.peers(), [])

    def test_a_goodbye_removes_the_peer(self):
        service = mdns.Service('_airdrop._tcp.local', 'aabbccddeeff', 8770, [])
        browser = self.browser()
        browser.feed(service.response(LAN), ('192.168.1.20', 5353), FakeTransport())
        browser.feed(service.response(LAN, alive=False), ('192.168.1.20', 5353), FakeTransport())
        self.assertEqual(browser.peers(), [])

    def test_ipv6_source_is_matched_by_scope(self):
        transport = FakeTransport()
        self.assertIs(transport.interface_of(('fe80::9', 5353, 0, 11)), LAN)
        self.assertIsNone(transport.interface_of(('fe80::9', 5353, 0, 12)))


if __name__ == '__main__':
    unittest.main()
