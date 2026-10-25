# SPDX-License-Identifier: MIT
"""Sender against receiver over the loopback interface: first in one
process, then as two separate `veer` processes, as a Mac and a PC would be,
with multicast DNS between them."""
import os
import plistlib
import queue
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from veer import archive, config, identity, mdns, netif, receiver, sender

LOOPBACK = netif.loopback()
PYTHON = [sys.executable, '-X', 'utf8', '-m', 'veer']


class Answer(receiver.Events):
    """Answers every offer the same way and records what happens."""

    def __init__(self, accept=True):
        self.accept = accept
        self.offers = []
        self.stored_names = []
        self.failures = []

    def asked(self, offer, sender_left):
        self.offers.append(offer)
        return self.accept

    def stored(self, offer, names, dest):
        self.stored_names.extend(names)

    def failed(self, offer, reason):
        self.failures.append(reason)


@unittest.skipIf(LOOPBACK is None, 'no loopback interface')
class InProcessTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.home = tempfile.TemporaryDirectory()
        cls.keys = os.path.join(cls.home.name, 'keys')
        cls.client = identity.client_context(cls.keys)

    @classmethod
    def tearDownClass(cls):
        cls.home.cleanup()

    def start(self, accept=True, announce=False):
        self.dest = tempfile.mkdtemp(dir=self.home.name)
        self.events = Answer(accept)
        settings = receiver.Settings(name='Test Receiver (Veer)', dest=self.dest, port=0,
                                     interfaces=[LOOPBACK], keys_dir=self.keys, announce=announce)
        running = receiver.start(settings, self.events)
        self.addCleanup(running.stop)
        return running

    def files(self, *contents):
        folder = tempfile.mkdtemp(dir=self.home.name)
        paths = []
        for number, data in enumerate(contents):
            path = os.path.join(folder, f'file{number}.bin')
            with open(path, 'wb') as out:
                out.write(data)
            paths.append(path)
        return sender.outgoing(paths)

    def read(self, name):
        with open(os.path.join(self.dest, name), 'rb') as f:
            return f.read()

    def test_discover_names_the_receiver(self):
        running = self.start()
        reply = sender.discover_at('127.0.0.1', running.port, self.client)
        answer = reply.plist()
        self.assertEqual(reply.status, 200)
        self.assertEqual(answer['ReceiverComputerName'], 'Test Receiver (Veer)')
        self.assertTrue(answer['IsAirDropable'])
        self.assertEqual(reply.headers['Server'], config.SERVER_VERSION)

    def test_accepted_files_are_stored_and_marked(self):
        running = self.start()
        big = os.urandom(3 * 1024 * 1024)
        files = self.files(b'hello', big)
        outcome = sender.deliver('127.0.0.1', running.port, self.client, 'Test Sender', files)
        self.assertEqual(outcome.result, sender.SENT, outcome)
        self.assertEqual(self.read('file0.bin'), b'hello')
        self.assertEqual(self.read('file1.bin'), big)
        [offer] = self.events.offers
        self.assertEqual(offer.sender_name, 'Test Sender')
        self.assertEqual([f[0] for f in offer.files], ['file0.bin', 'file1.bin'])
        self.assertEqual(offer.total_bytes, 5 + len(big))
        if os.name == 'nt':
            self.assertIn(b'ZoneId=3', self.read('file1.bin:Zone.Identifier'))

    def test_over_ipv6(self):
        running = self.start()
        outcome = sender.deliver('::1', running.port, self.client, 'v6', self.files(b'six'))
        self.assertEqual(outcome.result, sender.SENT)
        self.assertEqual(self.read('file0.bin'), b'six')

    def test_declined_offer_stores_nothing(self):
        running = self.start(accept=False)
        outcome = sender.deliver('127.0.0.1', running.port, self.client, 'x', self.files(b'no'))
        self.assertEqual((outcome.result, outcome.status), (sender.DECLINED, receiver.DECLINED_STATUS))
        self.assertEqual(os.listdir(self.dest), [])

    def connection(self, running):
        connection = sender.Connection('127.0.0.1', running.port, self.client, 10)
        self.addCleanup(connection.close)
        return connection

    def test_upload_without_ask_is_refused(self):
        running = self.start()
        connection = self.connection(running)
        body = b''.join(archive.encode_dvzip(archive.write_archive(
            [('./x', archive.FILE_MODE, 1, 0, (b'x',))])))
        connection.request('POST', '/Upload', body=body,
                           headers={'Content-Type': 'application/x-dvzip'})
        self.assertEqual(connection.getresponse().status, receiver.DECLINED_STATUS)
        self.assertEqual(os.listdir(self.dest), [])

    def test_links_are_stored_as_inert_shortcuts(self):
        running = self.start()
        reply = sender.post_plist(self.connection(running), '/Ask', {
            'TransferType': {'links': {}}, 'SenderComputerName': 'Mac',
            'Items': ['https://example.com/a', 'file:///C:/evil']})
        self.assertEqual(reply.status, 200)
        self.assertEqual(self.events.stored_names, ['example.com-a.url'])

    def test_an_xml_plist_ask_is_not_parsed(self):
        running = self.start()
        connection = self.connection(running)
        body = plistlib.dumps({'SenderComputerName': 'xml', 'Files': [{'FileName': 'a'}]})
        connection.request('POST', '/Ask', body=body)
        connection.getresponse().read()
        self.assertEqual(self.events.offers[0].sender_name, 'Unknown sender')
        self.assertEqual(self.events.offers[0].files, [])

    def test_body_whose_closing_chunk_comes_after_the_answer(self):
        # A Mac sends the final 0-chunk only once it has the answer, and
        # fails the transfer if the receiver resets the connection instead
        # of reading it. An iPhone sends no closing chunk at all.
        running = self.start()
        connection = self.connection(running)
        connection.connect()
        tid = 'T-1'
        sender.post_plist(connection, '/Ask', {'TransferID': {'id': tid},
                                               'TransferType': {'files': {}},
                                               'Files': [{'FileName': 'late.bin', 'FileSize': 100}]})
        payload = os.urandom(100)
        body = b''.join(archive.encode_dvzip(archive.write_archive(
            [('./late.bin', archive.FILE_MODE, len(payload), 0, (payload,))])))
        tls = connection.sock
        tls.sendall(b'POST /Upload HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-dvzip\r\n'
                    b'TransferID: ' + tid.encode() + b'\r\nTransfer-Encoding: chunked\r\n\r\n'
                    + b'%x\r\n%s\r\n' % (len(body), body))
        response = b''
        while b'\r\n\r\n' not in response:
            chunk = tls.recv(4096)
            self.assertTrue(chunk, 'closed before answering')
            response += chunk
        self.assertTrue(response.startswith(b'HTTP/1.1 200'))
        tls.sendall(b'0\r\n\r\n')
        while tls.recv(4096):  # raises ConnectionResetError on a reset
            pass
        self.assertEqual(self.read('late.bin'), payload)

    def test_peers_off_the_local_networks_are_refused(self):
        running = self.start()
        lan = netif.Interface('Ethernet', '', 11, 11, 'ethernet',
                              (__import__('ipaddress').IPv4Interface('192.168.1.10/24'),), ())
        running.server.settings.interfaces = [lan]
        self.assertTrue(running.server.is_local(('::ffff:192.168.1.77', 1, 0, 0)))
        self.assertTrue(running.server.is_local(('fe80::5', 1, 0, 11)))
        self.assertFalse(running.server.is_local(('fe80::5', 1, 0, 12)))
        self.assertFalse(running.server.is_local(('::ffff:8.8.8.8', 1, 0, 0)))
        self.assertTrue(running.server.is_local(('::1', 1, 0, 0)))

    def test_found_over_multicast_dns(self):
        running = self.start(announce=True)
        own_id = running.responder.service.instance
        browser = mdns.Browser(config.SERVICE_TYPE, [LOOPBACK])
        try:
            deadline = time.monotonic() + 10
            named = {}
            while time.monotonic() < deadline and 'Test Receiver (Veer)' not in named:
                named.update(sender.find_receivers(browser, self.client, 2))
        finally:
            browser.close()
        found = named.get('Test Receiver (Veer)')
        self.assertIsNotNone(found, 'the receiver was not found over multicast DNS')
        self.assertEqual(found.peer.instance_id, own_id)
        self.assertEqual(found.port, running.port)
        self.assertEqual(found.peer.flags, config.DEFAULT_FLAGS)


@unittest.skipIf(LOOPBACK is None, 'no loopback interface')
class TwoProcessesTest(unittest.TestCase):
    """`veer receive` and `veer send` as two programs, found by multicast DNS."""

    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.addCleanup(self.home.cleanup)
        self.dest = os.path.join(self.home.name, 'received')
        self.env = {**os.environ, config.ENV_HOME: self.home.name, 'PYTHONUNBUFFERED': '1'}
        # Unique per run, so that a receiver left over from another run on
        # this machine cannot answer instead.
        self.name = f'Receiver {os.getpid()}-{time.monotonic_ns() % 100000} (Veer)'

    def start_receiver(self):
        process = subprocess.Popen(
            PYTHON + ['receive', '--iface', LOOPBACK.name, '--port', '0', '--outdir', self.dest,
                      '--name', self.name, '--ask-timeout', '30'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            env=self.env, text=True, encoding='utf-8')
        self.addCleanup(self.stop, process)
        lines = queue.Queue()
        threading.Thread(target=lambda: [lines.put(line) for line in process.stdout],
                         daemon=True).start()
        self.wait_for(lines, 'is receiving as')
        return process, lines

    def stop(self, process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for stream in (process.stdin, process.stdout):
            if stream:
                stream.close()

    def wait_for(self, lines, text, seconds=30):
        deadline = time.monotonic() + seconds
        seen = []
        while time.monotonic() < deadline:
            try:
                line = lines.get(timeout=0.5)
            except queue.Empty:
                continue
            seen.append(line)
            if text in line:
                return line
        self.fail(f'{text!r} never appeared; output was:\n' + ''.join(seen))

    def send(self, path):
        return subprocess.Popen(
            PYTHON + ['send', path, '--iface', LOOPBACK.name, '--to', self.name,
                      '--name', 'Sender PC (Veer)', '--seconds', '20'],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=self.env, text=True,
            encoding='utf-8')

    def file(self, data):
        path = os.path.join(self.home.name, 'photo.jpg')
        with open(path, 'wb') as out:
            out.write(data)
        return path

    def test_send_accepted_in_the_console(self):
        process, lines = self.start_receiver()
        data = os.urandom(200_000)
        send = self.send(self.file(data))
        self.wait_for(lines, 'Accept? [y/N]')
        process.stdin.write('y\n')
        process.stdin.flush()
        self.wait_for(lines, 'Saved in')
        output, _ = send.communicate(timeout=60)
        self.assertEqual(send.returncode, 0, output)
        self.assertIn('Sent 1 file(s)', output)
        with open(os.path.join(self.dest, 'photo.jpg'), 'rb') as f:
            self.assertEqual(f.read(), data)

    def test_send_declined_in_the_console(self):
        process, lines = self.start_receiver()
        send = self.send(self.file(b'nope'))
        self.wait_for(lines, 'Accept? [y/N]')
        process.stdin.write('n\n')
        process.stdin.flush()
        output, _ = send.communicate(timeout=60)
        self.assertEqual(send.returncode, 3, output)
        self.assertIn('Declined', output)
        self.assertFalse(os.path.exists(os.path.join(self.dest, 'photo.jpg')))


if __name__ == '__main__':
    unittest.main()
