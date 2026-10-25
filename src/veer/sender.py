# SPDX-License-Identifier: MIT
# Adapted from airdrop/sender.py in winawdl, Copyright (c) 2026 Raphaël Richaud.
"""The AirDrop sender: finds receivers on the LAN, asks one, and uploads once
its user accepts. The receiver has to be visible to everyone."""
import http.client
import logging
import os
import plistlib
import socket
import ssl
import time
import uuid
from typing import NamedTuple

from . import archive, config, mdns

log = logging.getLogger('veer.sender')

CONNECT_SECONDS = 10
# The receiver's user has this long to accept.
ASK_SECONDS = 180
UPLOAD_IDLE_SECONDS = 30
IO_BLOCK_BYTES = 64 * 1024
PROGRESS_SECONDS = 2
MIB = 1024 * 1024
MAX_REPLY_BYTES = 1 * MIB
HEADERS = {
    'Content-Type': 'application/octet-stream',
    'Connection': 'keep-alive',
    'Accept': '*/*',
    'User-Agent': config.USER_AGENT,
    'Accept-Language': 'en-us',
    'Accept-Encoding': 'br, gzip, deflate',
}
# A receiver picks the app that takes a file by this type.
UNIFORM_TYPES = {
    '.jpg': 'public.jpeg', '.jpeg': 'public.jpeg', '.png': 'public.png',
    '.heic': 'public.heic', '.gif': 'com.compuserve.gif', '.tif': 'public.tiff',
    '.tiff': 'public.tiff', '.bmp': 'com.microsoft.bmp', '.webp': 'org.webmproject.webp',
    '.mov': 'com.apple.quicktime-movie', '.mp4': 'public.mpeg-4',
    '.m4v': 'com.apple.m4v-video', '.mp3': 'public.mp3', '.m4a': 'com.apple.m4a-audio',
    '.wav': 'com.microsoft.waveform-audio', '.pdf': 'com.adobe.pdf',
    '.txt': 'public.plain-text', '.rtf': 'public.rtf', '.html': 'public.html',
    '.csv': 'public.comma-separated-values-text', '.json': 'public.json',
    '.zip': 'public.zip-archive', '.docx': 'org.openxmlformats.wordprocessingml.document',
    '.xlsx': 'org.openxmlformats.spreadsheetml.sheet',
    '.pptx': 'org.openxmlformats.presentationml.presentation',
}
DEFAULT_UNIFORM_TYPE = 'public.data'

SENT, DECLINED, REFUSED = 'sent', 'declined', 'refused'


class Outgoing(NamedTuple):
    path: str
    name: str
    size: int
    mtime: float


class Unsendable(ValueError):
    pass


def outgoing(paths):
    """The files to send, refusing what an archive cannot hold apart."""
    files = []
    for path in paths:
        if not os.path.isfile(path):
            raise Unsendable(f'{path} is not a file')
        status = os.stat(path)
        files.append(Outgoing(path, os.path.basename(path), status.st_size, status.st_mtime))
    names = [file.name.lower() for file in files]
    if len(set(names)) != len(names):
        raise Unsendable('two of the files have the same name')
    return files


def split_address(text, default_port):
    """'192.168.1.5', '192.168.1.5:8770', 'fe80::1%11', '[fe80::1%11]:8770'
    -> (address, port)."""
    if text.startswith('['):
        address, _, rest = text[1:].partition(']')
        return address, int(rest[1:]) if rest.startswith(':') else default_port
    if text.count(':') == 1:
        address, port = text.split(':')
        return address, int(port)
    return text, default_port


class Connection(http.client.HTTPConnection):
    """HTTPS to an address that may be IPv4 or a scoped IPv6 one; the Host
    header carries it without its scope."""

    def __init__(self, address, port, context, timeout):
        bare, _, scope = address.partition('%')
        super().__init__(bare, port, timeout=timeout)
        self.scope = int(scope) if scope.isdigit() else 0
        self.context = context
        self.address = address

    def connect(self):
        ipv6 = ':' in self.host
        sock = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port, 0, self.scope) if ipv6 else (self.host, self.port))
            self.sock = self.context.wrap_socket(sock)
        except OSError:
            sock.close()
            raise


class Reply(NamedTuple):
    status: int
    reason: str
    headers: dict
    body: bytes

    def plist(self):
        """The body as a plist dictionary, or None."""
        try:
            value = plistlib.loads(self.body)
        except Exception:
            return None
        return value if isinstance(value, dict) else None


def read_reply(response):
    """The response, its body bounded: a peer on the network chooses its size."""
    data = response.read(MAX_REPLY_BYTES + 1)
    if len(data) > MAX_REPLY_BYTES:
        raise http.client.HTTPException(f'reply larger than {MAX_REPLY_BYTES} bytes')
    return Reply(response.status, response.reason, dict(response.getheaders()), data)


def post_plist(connection, path, value):
    body = plistlib.dumps(value, fmt=plistlib.FMT_BINARY)
    connection.request('POST', path, body=body, headers=HEADERS)
    return read_reply(connection.getresponse())


class Receiver(NamedTuple):
    """A receiver that answered /Discover with a name."""
    name: str
    model: str
    address: str
    port: int
    reply: Reply
    peer: object = None  # the mdns.Peer it was found as, if any


def discover_at(address, port, context, timeout=CONNECT_SECONDS):
    """POST /Discover to one address. Returns the Reply; raises OSError or
    http.client.HTTPException when it cannot be talked to."""
    connection = Connection(address, port, context, timeout)
    try:
        return post_plist(connection, '/Discover', {})
    finally:
        connection.close()


def identify(peer, context):
    """Try each address of an mdns.Peer in turn. Returns (Receiver or None,
    [(address, error or Reply)])."""
    attempts = []
    for address in peer.addresses:
        try:
            reply = discover_at(address, peer.port, context)
        except (OSError, http.client.HTTPException) as error:
            attempts.append((address, error))
            continue
        attempts.append((address, reply))
        answer = reply.plist() or {}
        name = answer.get('ReceiverComputerName')
        if reply.status == 200 and isinstance(name, str) and name:
            model = answer.get('ReceiverModelName')
            return Receiver(name, model if isinstance(model, str) else '?', address,
                            peer.port, reply, peer), attempts
        return None, attempts
    return None, attempts


def is_own(peer, own_ids=()):
    return peer.instance_id in own_ids


def find_receivers(browser, context, seconds, wanted=None, own_ids=()):
    """Receivers that answer with a name, as {name: Receiver}. Stops early at
    one whose name contains `wanted`, and a few seconds after the first."""
    named = {}
    tried = set()
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        for peer in browser.poll(0.5):
            key = (peer.instance, peer.addresses)
            if key in tried or is_own(peer, own_ids):
                continue
            tried.add(key)
            receiver, attempts = identify(peer, context)
            if receiver is None:
                last = attempts[-1][1] if attempts else 'no address'
                log.info('%s on %s did not answer with a name: %s', peer.instance_id,
                         peer.interface.name, describe_attempt(last))
                continue
            log.info('found %s (%s) at %s', receiver.name, receiver.model, receiver.address)
            named[receiver.name] = receiver
            if wanted and wanted.lower() in receiver.name.lower():
                return {receiver.name: receiver}
            deadline = min(deadline, time.monotonic() + 3)
    return named


def describe_attempt(result):
    if isinstance(result, Reply):
        return f'HTTP {result.status} {result.reason}'
    if isinstance(result, ssl.SSLError):
        return f'TLS error: {result.reason or result}'
    return str(result) or type(result).__name__


def uniform_type(name):
    return UNIFORM_TYPES.get(os.path.splitext(name)[1].lower(), DEFAULT_UNIFORM_TYPE)


def ask_body(sender_name, sender_id, files, transfer_id, model=config.DEFAULT_MODEL):
    """The request to send, with the keys a Mac's and an iPhone's own have,
    less their Apple identity and preview picture."""
    return {
        'TransferID': {'id': transfer_id},
        'TransferType': {'files': {}},
        'SenderID': sender_id,
        'BundleID': 'com.apple.finder',
        'SenderComputerName': sender_name,
        'SenderModelName': model,
        'Items': [],
        'Files': [{
            'FileName': file.name,
            'FileType': uniform_type(file.name),
            'FileSize': file.size,
            'FileBomPath': f'./{file.name}',
            'FileIsDirectory': False,
            'ConvertMediaFormats': False,
            'ShouldConvertMediaFormats': False,
        } for file in files],
        'ConvertMediaFormats': False,
    }


def _blocks(path, size):
    left = size
    with open(path, 'rb') as source:
        while left:
            block = source.read(min(IO_BLOCK_BYTES, left))
            if not block:
                break
            left -= len(block)
            yield block


def _members(files):
    # An Apple sender's archive starts with the folder its files are named in.
    yield '.', archive.DIRECTORY_MODE, 0, time.time(), ()
    for file in files:
        yield f'./{file.name}', archive.FILE_MODE, file.size, file.mtime, _blocks(file.path, file.size)


class Progress:
    def __init__(self, total, on_progress=None):
        self.total = total
        self.done = 0
        self.started = time.monotonic()
        self._last = self.started
        self._on_progress = on_progress

    def note(self, size):
        self.done += size
        if self._on_progress:
            self._on_progress(min(self.done, self.total), self.total)
        now = time.monotonic()
        if now - self._last >= PROGRESS_SECONDS:
            self._last = now
            log.info('sent %d%% at %.1f MB/s', self.done * 100 // max(self.total, 1), self.rate())

    def rate(self):
        return self.done / MIB / max(time.monotonic() - self.started, 0.001)


def archive_body(files, progress):
    """The upload: the CPIO archive of the files, in DVZip blocks."""
    def pieces():
        for piece in archive.write_archive(_members(files)):
            progress.note(len(piece))
            yield piece
    return archive.encode_dvzip(pieces())


def archive_bytes(files):
    return archive.archive_length([('.', 0)] + [(f'./{file.name}', file.size) for file in files])


class Outcome(NamedTuple):
    result: str           # SENT, DECLINED or REFUSED
    status: int
    reply: Reply
    seconds: float


def deliver(address, port, context, sender_name, files, sender_id=None,
            on_accepted=None, on_progress=None, ask_seconds=ASK_SECONDS):
    """Ask the receiver, and upload once its user accepts, on one connection."""
    sender_id = sender_id or mdns.new_service_id()
    started = time.monotonic()
    connection = Connection(address, port, context, CONNECT_SECONDS)
    try:
        transfer_id = str(uuid.uuid4()).upper()
        connection.connect()
        connection.sock.settimeout(ask_seconds)
        reply = post_plist(connection, '/Ask', ask_body(sender_name, sender_id, files, transfer_id))
        log.debug('answer to the ask: %d %s, headers %s, body %r', reply.status, reply.reason,
                  reply.headers, reply.plist() if reply.plist() is not None else reply.body[:200])
        if reply.status != 200:
            return Outcome(DECLINED, reply.status, reply, time.monotonic() - started)
        total = sum(file.size for file in files)
        if on_accepted:
            on_accepted(total)
        connection.sock.settimeout(UPLOAD_IDLE_SECONDS)
        progress = Progress(archive_bytes(files), on_progress)
        # The receiver ties the upload to what it accepted by the transfer's
        # identifier, on this same connection.
        connection.request('POST', '/Upload', body=archive_body(files, progress),
                           headers={**HEADERS, 'TotalBytes': str(total),
                                    'Content-Type': 'application/x-dvzip',
                                    'TransferID': transfer_id},
                           encode_chunked=True)
        upload = read_reply(connection.getresponse())
        result = SENT if upload.status == 200 else REFUSED
        if result == SENT:
            log.info('sent %.1f MB at %.1f MB/s', total / MIB, progress.rate())
        return Outcome(result, upload.status, upload, time.monotonic() - started)
    finally:
        connection.close()
