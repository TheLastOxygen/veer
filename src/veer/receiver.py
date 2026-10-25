# SPDX-License-Identifier: MIT
# Adapted from airdrop/receiver.py in winawdl, Copyright (c) 2026 Raphaël
# Richaud, itself adapted from bin/airdrop-serve.py in omdrop,
# Copyright (c) 2026 Brent Kearney.
"""The AirDrop receiver: announces this PC on the LAN and serves /Discover,
/Ask and /Upload over HTTPS. Every transfer is asked about first; nothing
received is ever opened."""
import ipaddress
import json
import logging
import os
import plistlib
import queue
import select
import socket
import ssl
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import NamedTuple

from . import config, identity, mdns, transfer

log = logging.getLogger('veer.receiver')

# What current Apple senders upload, and the gzip archive older ones do. The
# body says which framing it has.
UPLOAD_TYPES = ('application/x-dvzip', 'application/x-cpio')
# What a sender gets when the user says no. winawdl's choice; what a Mac
# answers has not been observed.
DECLINED_STATUS = 401
DEFAULT_MAX_RECEIVE_PERCENT = 30
DEFAULT_ASK_TIMEOUT = 120
# After answering an upload whose body had not ended: how long to wait for
# the rest of it. A Mac sends the closing chunk only once it has the answer,
# and fails the transfer if it is reset unread; an iPhone sends nothing and
# waits for us to close.
AFTER_ANSWER_SECONDS = 3
# Version 1 with no codecs makes the sender convert to formats Windows
# opens (JPEG, not HEIC). Sent in both the Discover and the Ask answer.
MEDIA_CAPABILITIES = json.dumps({'Version': 1}).encode()


class HandshakeFailed(Exception):
    """A TLS handshake that was already logged; usually a peer leaving."""


class Offer(NamedTuple):
    """What a sender asks to send."""
    sender_name: str
    sender_model: str
    address: str
    files: list    # of (name, uniform type, size or None)
    links: list    # of URLs, for a links transfer
    total_bytes: int

    def describe(self):
        if self.links:
            return f'{len(self.links)} link(s): ' + ', '.join(self.links[:5])
        listing = ', '.join(f'{name} ({_size(size)})' for name, _, size in self.files[:10])
        more = f' and {len(self.files) - 10} more' if len(self.files) > 10 else ''
        return f'{len(self.files)} file(s), {_size(self.total_bytes)}: {listing}{more}'


def _size(count):
    if not count:
        return 'size unknown'
    for unit in ('B', 'KB', 'MB', 'GB'):
        if count < 1000 or unit == 'GB':
            return f'{count:.0f} {unit}' if unit == 'B' else f'{count:.1f} {unit}'
        count /= 1000
    return str(count)


class Events:
    """What the program running the receiver is asked and told. This one
    declines everything; the CLI and the tests give their own."""

    def asked(self, offer, sender_left):
        """Return True to accept `offer`. `sender_left()` turns true once the
        sender has stopped waiting."""
        return False

    def upload_started(self, offer, tid, total):
        pass

    def upload_progress(self, tid, done, total):
        pass

    def stored(self, offer, names, dest):
        pass

    def failed(self, offer, reason):
        pass


class ConsolePrompt:
    """Asks in the console, one offer at a time. Lines are read by a thread
    of their own so that an offer can time out, or be withdrawn, while
    waiting for an answer."""

    YES = {'y', 'yes', 's', 'si', 'sì'}

    def __init__(self, timeout=DEFAULT_ASK_TIMEOUT, stream=None, out=None):
        self.timeout = timeout
        self.out = out or sys.stdout
        self._lines = queue.Queue()
        self._lock = threading.Lock()
        reader = threading.Thread(target=self._read, args=(stream or sys.stdin,),
                                  name='veer-stdin', daemon=True)
        reader.start()

    def _read(self, stream):
        for line in stream:
            self._lines.put(line.strip().lower())
        self._lines.put(None)

    def _say(self, text):
        print(text, file=self.out, flush=True)

    def __call__(self, offer, sender_left):
        with self._lock:
            # Anything typed before the question is not an answer to it.
            while not self._lines.empty():
                if self._lines.get_nowait() is None:
                    self._lines.put(None)
                    break
            self._say(f'\n{offer.sender_name} ({offer.address}) wants to send '
                      f'{offer.describe()}')
            self._say(f'Accept? [y/N] (declined automatically in {self.timeout} s)')
            waited = 0.0
            while waited < self.timeout:
                if sender_left():
                    self._say('The sender stopped waiting.')
                    return False
                try:
                    line = self._lines.get(timeout=0.5)
                except queue.Empty:
                    waited += 0.5
                    continue
                if line is None:
                    self._lines.put(None)
                    self._say('No console input: declined.')
                    return False
                accepted = line in self.YES
                self._say('Accepted.' if accepted else 'Declined.')
                return accepted
            self._say('No answer: declined.')
            return False


@dataclass
class Settings:
    name: str = field(default_factory=config.default_device_name)
    model: str = config.DEFAULT_MODEL
    dest: str = field(default_factory=config.default_download_dir)
    port: int = config.DEFAULT_PORT
    flags: int = config.DEFAULT_FLAGS
    max_receive_percent: int = DEFAULT_MAX_RECEIVE_PERCENT
    interfaces: list = field(default_factory=list)
    keys_dir: str = None
    announce: bool = True


def _peer_ip(address):
    ip = ipaddress.ip_address(address.split('%')[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


class Receiver(ThreadingHTTPServer):
    """Threaded because a sender opens several connections at once. Listens
    on IPv6 and IPv4 at once, and takes connections only from the local
    networks of the chosen interfaces."""

    address_family = socket.AF_INET6
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, settings, events=None, context=None):
        self.settings = settings
        self.events = events or Events()
        self.live = set()
        super().__init__(('::', settings.port), Handler, bind_and_activate=False)
        try:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            self.server_bind()
            self.server_activate()
        except OSError:
            self.server_close()
            raise
        if context is not None:
            self.socket = context.wrap_socket(self.socket, server_side=True,
                                              do_handshake_on_connect=False)

    @property
    def port(self):
        return self.server_address[1]

    def is_local(self, client_address):
        try:
            ip = _peer_ip(client_address[0])
        except ValueError:
            return False
        if ip.is_loopback:
            return True
        for interface in self.settings.interfaces:
            if ip.version == 6 and ip.is_link_local:
                if len(client_address) > 3 and client_address[3] == interface.ipv6_index:
                    return True
            elif any(ip in net.network for net in interface.ipv4 + interface.ipv6
                     if not net.ip.is_link_local):
                return True
        return False

    def verify_request(self, request, client_address):
        if self.is_local(client_address):
            return True
        log.warning('refused a connection from %s: not on a local network', client_address[0])
        return False

    def process_request(self, request, client_address):
        log.debug('connection from [%s]:%s', client_address[0], client_address[1])
        self.live.add(request)
        super().process_request(request, client_address)

    def shutdown_request(self, request):
        self.live.discard(request)
        super().shutdown_request(request)

    def handle_error(self, request, client_address):
        # A sender ends its keep-alive session with a reset once it is done,
        # and one that stopped waiting is gone before its answer is written.
        if isinstance(sys.exc_info()[1], (ConnectionError, ssl.SSLError, HandshakeFailed,
                                          TimeoutError)):
            return
        super().handle_error(request, client_address)


class Handler(BaseHTTPRequestHandler):
    """/Discover and /Ask arrive chunked from Apple senders, /Upload as
    application/x-dvzip. Ask and Upload share one connection, so each body is
    read once and in place, and the upload is tied to the ask before it."""

    protocol_version = 'HTTP/1.1'
    server_version = config.SERVER_VERSION
    sys_version = ''
    # The offer accepted on this connection, and its transfer id.
    accepted = None
    accepted_tid = None

    def setup(self):
        self.request.settimeout(transfer.READ_IDLE_TIMEOUT_SECONDS)
        # The handshake runs on this connection's own thread: done in accept,
        # one peer dropping off mid-handshake would block every later one.
        try:
            self.request.do_handshake()
        except OSError as error:
            log.info('TLS handshake with %s failed: %s', self.client_address[0], error)
            raise HandshakeFailed from error
        super().setup()

    def sender_left(self):
        """Whether the sender has closed this connection. Only asked while it
        is owed an answer and so has nothing to send."""
        if not select.select([self.request], [], [], 0)[0]:
            return False
        self.request.settimeout(0)
        try:
            return not self.rfile.peek(1)
        except (ssl.SSLWantReadError, BlockingIOError):
            return False
        except OSError:
            return True
        finally:
            self.request.settimeout(transfer.READ_IDLE_TIMEOUT_SECONDS)

    def handle_expect_100(self):
        # An upload is acknowledged only once its framing and size are checked.
        if self.path == '/Upload':
            return True
        return super().handle_expect_100()

    def reject(self, status, reason):
        log.warning('%s from %s rejected (%d): %s', self.path, self.client_address[0],
                    status, reason)
        self.send_response(status)
        self.send_header('Content-Length', '0')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.close_connection = True

    def answer(self, body):
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_GET(self):
        self.answer(b'\n')

    def do_POST(self):
        log.debug('%s %s headers: %s', self.command, self.path, dict(self.headers.items()))
        if self.path == '/Upload':
            self.handle_upload()
            return
        if self.path not in ('/Discover', '/Ask'):
            self.reject(400, 'unknown endpoint')
            return
        try:
            body = transfer.read_small_body(self.rfile, self.headers)
        except TimeoutError:
            self.reject(408, 'request body read timed out')
            return
        except transfer.RequestBodyError as error:
            self.reject(error.status, str(error))
            return
        if self.path == '/Discover':
            log.info('discovered by %s', self.client_address[0])
            self.answer(self.identity_plist())
        else:
            self.handle_ask(body)

    def identity_plist(self):
        settings = self.server.settings
        return plistlib.dumps({
            'ReceiverComputerName': settings.name,
            'ReceiverModelName': settings.model,
            'ReceiverMediaCapabilities': MEDIA_CAPABILITIES,
            'IsAirDropable': True,
        }, fmt=plistlib.FMT_BINARY)

    def read_offer(self, body):
        # Binary only: an XML plist is not what senders send, and its parser
        # is a bigger surface (unbounded nesting).
        try:
            ask = plistlib.loads(body, fmt=plistlib.FMT_BINARY)
        except Exception as error:
            log.error('ask: undecodable %d-byte body: %r', len(body), error)
            ask = {}
        if not isinstance(ask, dict):
            ask = {}
        log.debug('ask: %s', transfer.outline(ask))
        files = [f for f in (ask.get('Files') or []) if isinstance(f, dict)]
        items = [i for i in (ask.get('Items') or []) if isinstance(i, str)]
        kinds = ask.get('TransferType') if isinstance(ask.get('TransferType'), dict) else {}
        listed = []
        for entry in files[:transfer.MAX_ARCHIVE_MEMBERS + 1]:
            size = entry.get('FileSize')
            listed.append((transfer.safe_name(str(entry.get('FileName', '')), 'file'),
                           str(entry.get('FileType', '')),
                           size if isinstance(size, int) and size >= 0 else None))
        links = [i for i in items if transfer.is_web_link(i)] if 'links' in kinds else []
        total = sum(size or 0 for _, _, size in listed)
        tid = ask.get('TransferID')
        tid = tid.get('id') if isinstance(tid, dict) else tid
        name = ask.get('SenderComputerName')
        model = ask.get('SenderModelName')
        offer = Offer(transfer.safe_name(name, 'Unknown sender') if isinstance(name, str)
                      else 'Unknown sender',
                      model if isinstance(model, str) else '?',
                      self.client_address[0].split('%')[0].removeprefix('::ffff:'),
                      listed, links, total)
        return offer, (tid if isinstance(tid, str) else None), len(files) + len(items)

    def handle_ask(self, body):
        offer, tid, count = self.read_offer(body)
        log.info('ask from %s (%s) at %s: %s', offer.sender_name, offer.sender_model,
                 offer.address, offer.describe())
        if count > transfer.MAX_ARCHIVE_MEMBERS:
            self.reject(413, f'ask exceeds {transfer.MAX_ARCHIVE_MEMBERS}-item limit')
            return
        events = self.server.events
        if not events.asked(offer, self.sender_left):
            self.reject(DECLINED_STATUS, 'declined here')
            return
        # A links transfer has no /Upload: the URLs are in the ask, so
        # accepting it is the transfer. They are stored and never opened.
        if offer.links:
            dest = self.server.settings.dest
            stored = [transfer.store_link(url, dest) for url in offer.links]
            events.stored(offer, stored, dest)
        else:
            self.accepted, self.accepted_tid = offer, tid
        self.answer(self.identity_plist())

    def receive_archive(self, raw, budget, plan, deadline, tid, on_progress):
        """Store the upload's files; returns their names and whether the body
        ended. Apple senders do not always end it."""
        dest = self.server.settings.dest

        def expect_little_more():
            deadline.idle_seconds = transfer.END_MARKER_WAIT_SECONDS
            self.request.settimeout(deadline.idle_seconds)

        try:
            wire_bytes = transfer.read_request_body(
                self.rfile, self.headers,
                transfer.EndWatchingFile(raw, expect_little_more, on_progress),
                budget.byte_limit, disk=dest, plan=plan, deadline=deadline)
        except TimeoutError as stall:
            if not deadline.between_chunks:
                raise
            try:
                written = transfer.store_upload(raw, dest, tid, budget)
            except transfer.UploadLimitError:
                raise
            except ValueError:
                raise stall from None
            log.info('upload %s: %d bytes received, a complete archive with no end marker',
                     tid, deadline.transferred)
            return written, False
        log.info('upload %s: %d bytes received', tid, wire_bytes)
        return transfer.store_upload(raw, dest, tid, budget), True

    def handle_upload(self):
        settings = self.server.settings
        events = self.server.events
        offer, asked_tid = self.accepted, self.accepted_tid
        self.accepted = self.accepted_tid = None
        ctype = self.headers.get('Content-Type', '').split(';')[0].strip().lower()
        if offer is None:
            self.reject(DECLINED_STATUS, 'upload follows no accepted ask on this connection')
            return
        header_tid = self.headers.get('TransferID')
        if asked_tid and header_tid and header_tid != asked_tid:
            self.reject(DECLINED_STATUS, 'upload is for another transfer than the one accepted')
            return
        if ctype not in UPLOAD_TYPES:
            self.reject(415, f'unsupported Content-Type {ctype!r}')
            return
        if not transfer.UPLOAD_SLOTS.acquire(blocking=False):
            self.reject(503, 'too many uploads in progress')
            return
        tid = transfer.safe_name(header_tid or asked_tid or '', 'upload')
        total = announced_bytes(self.headers) or offer.total_bytes
        deadline = transfer.ReadDeadline()
        plan = None
        refused = None
        try:
            os.makedirs(settings.dest, exist_ok=True)
            budget = transfer.ReceiveBudget(settings.dest, settings.max_receive_percent)
            plan = transfer.body_plan(self.headers, budget.byte_limit)
            if total and total > budget.byte_limit:
                raise transfer.UploadLimitError(
                    f'{total} bytes announced, {budget.byte_limit} allowed')
            events.upload_started(offer, tid, total)
            if self.headers.get('Expect', '').lower() == '100-continue':
                self.send_response_only(100)
                self.end_headers()
            with tempfile.TemporaryFile(dir=settings.dest) as raw:
                written, ended = self.receive_archive(
                    raw, budget, plan, deadline, tid,
                    lambda done: events.upload_progress(tid, done, total))
            log.info('upload %s: stored %s', tid, ', '.join(written))
        except TimeoutError as error:
            expected = plan[1] if plan else None
            refused = 408, f'upload {tid}: {deadline.stall_report(error, expected)}'
        except (transfer.BodyTooLarge, transfer.UploadLimitError) as error:
            refused = 413, str(error)
        except transfer.RequestBodyError as error:
            refused = error.status, str(error)
        except OSError as error:
            refused = 507, f'storage failed: {error}'
        except Exception as error:
            refused = 422, f'upload is not a valid bounded archive: {error}'
        finally:
            transfer.UPLOAD_SLOTS.release()
            self.request.settimeout(transfer.READ_IDLE_TIMEOUT_SECONDS)
        if refused:
            events.failed(offer, refused[1])
            self.reject(*refused)
            return
        events.stored(offer, written, settings.dest)
        self.send_response(200)
        self.send_header('Content-Length', '0')
        if not ended:
            self.send_header('Connection', 'close')
        self.end_headers()
        if not ended:
            self.wfile.flush()
            self.finish_unended_body()

    def finish_unended_body(self):
        """Read what the sender still sends after the answer (a Mac's closing
        chunk), so the close that follows is clean and not a reset."""
        self.close_connection = True
        self.request.settimeout(AFTER_ANSWER_SECONDS)
        # The read that stalled has left rfile refusing to read ("timed out
        # object"), so what it still buffers is taken first, then the rest
        # comes straight from the socket.
        try:
            self.rfile.read1(transfer.IO_CHUNK_BYTES)
        except (OSError, ValueError):
            pass
        deadline = time.monotonic() + AFTER_ANSWER_SECONDS
        try:
            while time.monotonic() < deadline and self.request.recv(transfer.IO_CHUNK_BYTES):
                pass
        except (OSError, ValueError):
            pass

    def log_message(self, fmt, *args):
        log.debug('%s %s', self.client_address[0], fmt % args)


def announced_bytes(headers):
    """The size a sender gives for what it uploads, or None without a usable one."""
    try:
        total = int(headers.get('TotalBytes', ''))
    except ValueError:
        return None
    return total if total > 0 else None


class Running:
    """A receiver serving on its own thread, with its announcement."""

    def __init__(self, server, responder, thread):
        self.server = server
        self.responder = responder
        self.thread = thread

    @property
    def port(self):
        return self.server.port

    def stop(self):
        if self.responder:
            self.responder.stop()
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()


def start(settings, events=None, context=None, service_id=None):
    """Bind, announce and serve in the background. Raises OSError if the
    port is taken or no interface can carry multicast DNS."""
    os.makedirs(settings.dest, exist_ok=True)
    context = context or identity.server_context(settings.keys_dir)
    server = Receiver(settings, events, context)
    responder = None
    try:
        if settings.announce:
            service = mdns.Service(config.SERVICE_TYPE, service_id or mdns.new_service_id(),
                                   server.port, [f'flags={settings.flags}'])
            responder = mdns.Responder(service, settings.interfaces)
            responder.start()
            log.info('announcing %s on %s', service.instance_name,
                     ', '.join(i.name for i in responder.interfaces))
    except OSError:
        server.server_close()
        raise
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.25},
                              name='veer-https', daemon=True)
    thread.start()
    return Running(server, responder, thread)
