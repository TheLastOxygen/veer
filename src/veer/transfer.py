# SPDX-License-Identifier: MIT
# Adapted from airdrop/transfer.py in winawdl, Copyright (c) 2026 Raphaël
# Richaud, itself adapted from bin/airdrop-serve.py in omdrop,
# Copyright (c) 2026 Brent Kearney.
"""Bounded reading, decoding and storing of what an AirDrop sender uploads.
The bytes come from whoever is on the network, so every step has a ceiling:
body size, decoded size, member count, read rate and free disk space."""
import contextlib
import io
import logging
import os
import re
import shutil
import socket
import tempfile
import threading
import time
import unicodedata
import zlib
from urllib.parse import urlsplit

from . import archive

log = logging.getLogger('veer.transfer')

KIB = 1024
MIB = 1024 * KIB
GIB = 1024 * MIB

READ_IDLE_TIMEOUT_SECONDS = 30
# How long to wait for the marker that ends a body once the archive in it is
# complete. An iPhone sends none after a video or a Live Photo.
END_MARKER_WAIT_SECONDS = 2
INITIAL_READ_SECONDS = 60
MIN_READ_BYTES_PER_SECOND = 64 * KIB
MAX_METADATA_BYTES = 1 * MIB
MAX_ARCHIVE_MEMBERS = 512
MIN_FREE_BYTES = 1 * GIB
DISK_CHECK_INTERVAL = 16 * MIB
IO_CHUNK_BYTES = 64 * KIB
MAX_CHUNK_LINE_BYTES = 128
MAX_TRAILER_BYTES = 8 * KIB
MAX_CONCURRENT_UPLOADS = 2
UPLOAD_SLOTS = threading.BoundedSemaphore(MAX_CONCURRENT_UPLOADS)
MAX_NAME_UNITS = 255
MAX_NAME_ATTEMPTS = 10000
MAX_LINK_BYTES = 8 * KIB
LIVE_PHOTO_FOLDER_SUFFIX = '.pvt'
LIVE_PHOTO_METADATA = 'metadata.plist'

# Separators, what Windows forbids (a colon selects an alternate data stream),
# control characters, and bidi overrides: "gpj.<U+202E>exe" shows as "exe.jpg".
UNSAFE_CHAR = re.compile(
    '[/\\\\\x00<>:"|?*]|[‪-‮⁦-⁩​-‏﻿]|[\x01-\x1f\x7f-\x9f]')
# Windows resolves these to devices whatever extension follows.
DEVICE_NAME = re.compile('^(con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³])$',
                         re.IGNORECASE)
# Zone 3 is "Internet": Windows then treats the file like a browser download.
ZONE_MARK = b'[ZoneTransfer]\r\nZoneId=3\r\n'
# A line break inside a stored link would add keys to the shortcut file, such
# as an icon path on a remote share.
LINK_BREAKING_CHAR = re.compile(r'[\x00-\x20\x7f-\x9f]')


class RequestBodyError(ValueError):
    status = 400


class BodyTooLarge(RequestBodyError):
    status = 413


class UploadLimitError(ValueError):
    pass


class ReceiveBudget:
    """Byte budget for one upload, based on current free output-disk space."""

    def __init__(self, dest, percent):
        self.free_bytes = shutil.disk_usage(dest).free
        percent_bytes = self.free_bytes * percent // 100
        reservable = max(0, self.free_bytes - MIN_FREE_BYTES)
        self.byte_limit = min(percent_bytes, reservable)
        self.percent = percent
        if self.byte_limit <= 0:
            raise UploadLimitError(
                f'not enough free space while preserving {MIN_FREE_BYTES} bytes')


class ReadRateTimeout(socket.timeout):
    """The body is still arriving, but slower than the minimum read rate."""


class ReadDeadline:
    """Require sustained progress as well as an idle-socket timeout."""

    def __init__(self):
        self.started = time.monotonic()
        self.transferred = 0
        self.idle_seconds = READ_IDLE_TIMEOUT_SECONDS
        self.awaiting = 'the first byte'
        self.chunks = 0
        # True while the next thing due is a chunk header: every chunk so far
        # arrived whole, so the body may be all there bar its end marker.
        self.between_chunks = False

    def note(self, size):
        self.transferred += size
        allowed = INITIAL_READ_SECONDS + self.transferred / MIN_READ_BYTES_PER_SECOND
        if time.monotonic() > self.started + allowed:
            raise ReadRateTimeout('request body did not meet minimum read rate')

    def stall_report(self, error, expected):
        why = (f'slower than {MIN_READ_BYTES_PER_SECOND} bytes/s'
               if isinstance(error, ReadRateTimeout)
               else f'nothing arrived for {self.idle_seconds} s')
        of = f' of {expected}' if expected is not None else ''
        return (f'request body read timed out, {why}: {self.transferred}{of} '
                f'bytes in {time.monotonic() - self.started:.1f} s, then '
                f'waiting for {self.awaiting} after {self.chunks} chunks')


class LimitedWriter:
    """Count writes, enforce a byte ceiling, and preserve free disk space on
    the volume holding `disk`; None skips that check for in-memory targets."""

    def __init__(self, target, limit, label, limit_error=UploadLimitError, disk=None):
        self.target = target
        self.limit = limit
        self.label = label
        self.limit_error = limit_error
        self.disk = disk
        self.total = 0
        self._until_disk_check = 0

    @property
    def remaining(self):
        return self.limit - self.total

    def write(self, data):
        if not data:
            return 0
        size = len(data)
        if size > self.remaining:
            raise self.limit_error(f'{self.label} exceeds {self.limit}-byte limit')
        if self.disk and size >= self._until_disk_check:
            if shutil.disk_usage(self.disk).free < MIN_FREE_BYTES + DISK_CHECK_INTERVAL:
                raise UploadLimitError(
                    f'{self.label} stopped to preserve {MIN_FREE_BYTES} bytes free')
            self._until_disk_check = DISK_CHECK_INTERVAL
        written = self.target.write(data)
        if written is not None and written != size:
            raise OSError(f'short write for {self.label}: {written} of {size} bytes')
        self.total += size
        self._until_disk_check -= size
        return size


def body_plan(headers, limit):
    """Validate framing before sending 100 Continue or reading any body."""
    encoding = headers.get('Transfer-Encoding', '')
    if encoding:
        encodings = [part.strip().lower() for part in encoding.split(',')]
        if encodings != ['chunked']:
            raise RequestBodyError(f'unsupported Transfer-Encoding: {encoding!r}')
        return 'chunked', None
    value = headers.get('Content-Length')
    if value is None:
        raise RequestBodyError('request body needs Content-Length or chunked encoding')
    try:
        length = int(value)
    except (TypeError, ValueError):
        raise RequestBodyError(f'invalid Content-Length: {value!r}') from None
    if length < 0:
        raise RequestBodyError(f'invalid Content-Length: {value!r}')
    if length > limit:
        raise BodyTooLarge(f'request body exceeds {limit}-byte limit')
    return 'length', length


def _copy_exact(source, writer, size, truncated, deadline):
    # read1 returns what has arrived instead of waiting for a full chunk, so a
    # stalled body is counted to the byte.
    read = getattr(source, 'read1', source.read)
    left = size
    while left:
        deadline.awaiting = f'the last {left} of {size} bytes'
        data = read(min(left, IO_CHUNK_BYTES))
        if not data:
            raise RequestBodyError(truncated)
        deadline.note(len(data))
        writer.write(data)
        left -= len(data)


def _read_chunked(rfile, writer, deadline):
    while True:
        deadline.awaiting = 'a chunk header'
        deadline.between_chunks = deadline.chunks > 0
        line = rfile.readline(MAX_CHUNK_LINE_BYTES + 1)
        deadline.between_chunks = False
        deadline.note(len(line))
        if not line or len(line) > MAX_CHUNK_LINE_BYTES or not line.endswith(b'\n'):
            raise RequestBodyError('invalid or overlong chunk-size line')
        token = line.split(b';', 1)[0].strip()
        try:
            size = int(token, 16)
        except ValueError:
            raise RequestBodyError(f'invalid chunk size: {token[:40]!r}') from None
        if size < 0:
            raise RequestBodyError('negative chunk size')
        if size == 0:
            trailers = 0
            while True:
                deadline.awaiting = 'the line that ends the body'
                line = rfile.readline(MAX_CHUNK_LINE_BYTES + 1)
                deadline.note(len(line))
                trailers += len(line)
                if (not line or len(line) > MAX_CHUNK_LINE_BYTES
                        or trailers > MAX_TRAILER_BYTES):
                    raise RequestBodyError('invalid or overlong chunk trailers')
                if line in (b'\r\n', b'\n'):
                    return
        if size > writer.remaining:
            raise BodyTooLarge(f'request body exceeds {writer.limit}-byte limit')
        _copy_exact(rfile, writer, size, 'truncated chunk data', deadline)
        deadline.awaiting = 'the line break after a chunk'
        ending = rfile.read(2)
        deadline.note(len(ending))
        if ending != b'\r\n':
            raise RequestBodyError('chunk data missing CRLF')
        deadline.chunks += 1


def read_request_body(rfile, headers, target, limit, *, disk=None, plan=None, deadline=None):
    """Stream one framed request body into target under byte and time limits."""
    mode, length = plan or body_plan(headers, limit)
    deadline = deadline or ReadDeadline()
    writer = LimitedWriter(target, limit, 'request body', BodyTooLarge, disk)
    if mode == 'chunked':
        _read_chunked(rfile, writer, deadline)
    else:
        _copy_exact(rfile, writer, length, 'truncated request body', deadline)
    return writer.total


def read_small_body(rfile, headers, limit=MAX_METADATA_BYTES):
    body = io.BytesIO()
    read_request_body(rfile, headers, body, limit)
    return body.getvalue()


def _inflate(decoder, data, writer):
    while data:
        output = decoder.decompress(data, min(IO_CHUNK_BYTES, writer.remaining + 1))
        writer.write(output)
        if decoder.unconsumed_tail:
            data = decoder.unconsumed_tail
        else:
            return


def _decode_compressed_block(source, size, writer):
    decoder = zlib.decompressobj()
    left = size
    while left:
        data = source.read(min(left, IO_CHUNK_BYTES))
        if not data:
            raise ValueError(f'truncated compressed block: {left} bytes missing')
        left -= len(data)
        _inflate(decoder, data, writer)
        if decoder.unused_data:
            raise ValueError('compressed block has trailing data')
    writer.write(decoder.flush())
    if not decoder.eof:
        raise ValueError('truncated compressed block')


def decode_upload(source, target, byte_limit, disk=None):
    """Stream a gzip or DVZip body from `source` into a bounded CPIO stream."""
    writer = LimitedWriter(target, byte_limit, 'decompressed archive', disk=disk)
    source.seek(0)
    magic = source.read(2)
    source.seek(0)
    if magic == archive.GZIP_MAGIC:
        decoder = zlib.decompressobj(zlib.MAX_WBITS | 16)
        while True:
            data = source.read(IO_CHUNK_BYTES)
            if not data:
                break
            _inflate(decoder, data, writer)
            if decoder.unused_data:
                raise ValueError('gzip body has trailing data')
        writer.write(decoder.flush())
        if not decoder.eof:
            raise ValueError('truncated gzip body')
        return writer.total
    while True:
        header = source.read(archive.DVZIP_HEADER_BYTES)
        if not header:
            return writer.total
        if len(header) != archive.DVZIP_HEADER_BYTES:
            raise ValueError(f'truncated DVZip block header: {len(header)} bytes')
        value = int.from_bytes(header, 'big')
        size = value & ~archive.DVZIP_STORED
        if value & archive.DVZIP_STORED:
            left = size
            while left:
                data = source.read(min(left, IO_CHUNK_BYTES))
                if not data:
                    raise ValueError(f'truncated stored block: {left} bytes missing')
                writer.write(data)
                left -= len(data)
        else:
            _decode_compressed_block(source, size, writer)


class EndWatchingFile:
    """Writes an upload to `target` and calls `on_complete`, once, when what
    has been written holds a complete archive. `on_progress` is told how many
    bytes of the archive have arrived, or of the body if that cannot be read."""

    def __init__(self, target, on_complete, on_progress=None):
        self._target = target
        self._on_complete = on_complete
        self._on_progress = on_progress
        self._watcher = archive.ArchiveEndWatcher()
        self._complete = False
        self._wire = 0

    @property
    def complete(self):
        return self._complete

    def write(self, data):
        written = self._target.write(data)
        self._wire += len(data)
        if not self._complete and self._watcher.feed(data):
            self._complete = True
            self._on_complete()
        if self._on_progress:
            self._on_progress(self._wire if self._watcher.gave_up else self._watcher.decoded)
        return written


def safe_name(name, fallback):
    """One non-hidden filesystem component from sender-controlled text."""
    name = unicodedata.normalize('NFC', name.replace('\\', '/').rsplit('/', 1)[-1])
    # Windows drops trailing dots and spaces itself, which would let two
    # different names land on one file.
    name = UNSAFE_CHAR.sub('', name).strip().lstrip('.').rstrip('. ')
    stem, ext = os.path.splitext(name)
    if DEVICE_NAME.match(stem.split('.', 1)[0]):
        stem = '_' + stem
    while len((stem + ext).encode('utf-16-le')) // 2 > MAX_NAME_UNITS and stem:
        stem = stem[:-1]
    return (stem + ext) or fallback


def numbered(name, number):
    stem, ext = os.path.splitext(name)
    return name if number == 0 else f'{stem}-{number}{ext}'


def open_new(dest, name):
    """Create dest/name atomically without clobbering an existing file."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0)
    for i in range(MAX_NAME_ATTEMPTS):
        candidate = numbered(name, i)
        try:
            fd = os.open(os.path.join(dest, candidate), flags, 0o644)
        except FileExistsError:
            continue
        return candidate, os.fdopen(fd, 'wb')
    raise FileExistsError(name)


def mark_as_downloaded(path):
    """Tag a stored file as coming from the Internet zone (the Mark of the
    Web), so Windows warns before running or opening it. Only NTFS has the
    stream this lives in; elsewhere there is nothing to tag."""
    if os.name != 'nt':
        return False
    try:
        with open(path + ':Zone.Identifier', 'wb') as mark:
            mark.write(ZONE_MARK)
    except OSError as error:
        log.warning('could not mark %s as downloaded: %s', os.path.basename(path), error)
        return False
    return True


class ExtractionBudget:
    def __init__(self, byte_limit):
        self.byte_limit = byte_limit
        self.members = 0
        self.output_bytes = 0

    def count_member(self):
        self.members += 1
        if self.members > MAX_ARCHIVE_MEMBERS:
            raise UploadLimitError(f'archive exceeds {MAX_ARCHIVE_MEMBERS}-member limit')


class ExtractedFileWriter(LimitedWriter):
    def __init__(self, target, budget, name, disk):
        super().__init__(target, budget.byte_limit, f'file {name!r}', disk=disk)
        self.budget = budget

    def write(self, data):
        if self.budget.output_bytes + len(data) > self.budget.byte_limit:
            raise UploadLimitError(f'archive output exceeds {self.budget.byte_limit}-byte limit')
        written = super().write(data)
        self.budget.output_bytes += written
        return written


def live_photo_folder(pathname):
    """The folder a Live Photo's member sits in, or None for any other file."""
    for part in pathname.split('/')[:-1]:
        if part.lower().endswith(LIVE_PHOTO_FOLDER_SUFFIX):
            return part
    return None


def free_number(dest, stem):
    """The first number under which no file in dest has this stem, whatever
    its extension; 0 stands for the bare stem."""
    taken = {os.path.splitext(name)[0].casefold() for name in os.listdir(dest)}
    for number in range(MAX_NAME_ATTEMPTS):
        if numbered(stem, number).casefold() not in taken:
            return number
    raise FileExistsError(stem)


def _extract(source, dest, budget, created):
    written = []
    live_photo_numbers = {}
    for entry in archive.read_entries(source):
        budget.count_member()
        log.debug('archive member %r, %d bytes, %s', entry.pathname, entry.size,
                  'a file' if entry.isfile else 'not a file')
        # Archive paths are split on "/" alone: a name may itself hold
        # backslashes. Folders are flattened: only regular files are stored,
        # each under its own name. AppleDouble companions ("._name") carry
        # Finder metadata only, and a Live Photo's metadata only pairs its two
        # files for Photos.
        leaf = entry.pathname.rsplit('/', 1)[-1]
        live_photo = live_photo_folder(entry.pathname)
        if (not entry.isfile or leaf.startswith('._')
                or (live_photo and leaf == LIVE_PHOTO_METADATA)):
            continue
        if budget.output_bytes + entry.size > budget.byte_limit:
            raise UploadLimitError(f'archive declares more than {budget.byte_limit} output bytes')
        wanted = safe_name(entry.pathname, 'file')
        if live_photo:
            # The still and the video share a stem, and keep sharing it when
            # an earlier file has taken the name of one of them.
            if live_photo not in live_photo_numbers:
                live_photo_numbers[live_photo] = free_number(dest, os.path.splitext(wanted)[0])
            wanted = numbered(wanted, live_photo_numbers[live_photo])
        name, output = open_new(dest, wanted)
        created.append(name)
        with output:
            sink = ExtractedFileWriter(output, budget, name, dest)
            for block in entry.blocks():
                sink.write(block)
        mark_as_downloaded(os.path.join(dest, name))
        written.append(name)
    return written


def store_upload(raw, dest, tid, receive_budget):
    """Decode the upload in `raw` and extract its regular files into dest,
    removing every output on failure. Returns the stored names."""
    created = []
    try:
        with tempfile.TemporaryFile(dir=dest) as cpio_stream:
            raw.seek(0)
            log.debug('upload %s: body starts with %s', tid, raw.read(8).hex())
            decoded = decode_upload(raw, cpio_stream, receive_budget.byte_limit, dest)
            # The wire copy is no longer needed. Release its blocks before the
            # extracted files begin consuming space.
            raw.seek(0)
            raw.truncate(0)
            cpio_stream.seek(0)
            log.info('upload %s: decoded to %d bytes', tid, decoded)
            return _extract(cpio_stream, dest, ExtractionBudget(receive_budget.byte_limit), created)
    except Exception:
        for name in reversed(created):
            with contextlib.suppress(FileNotFoundError):
                os.unlink(os.path.join(dest, name))
        raise


def is_web_link(item):
    return (isinstance(item, str) and item.startswith(('http://', 'https://'))
            and len(item.encode('utf-8')) <= MAX_LINK_BYTES
            and not LINK_BREAKING_CHAR.search(item))


def store_link(url, dest):
    """Write a received URL into dest as an inert .url shortcut and return the
    stored name. The URL is written as a value and never opened here."""
    parts = urlsplit(url)
    stem = '-'.join(p for p in (parts.netloc, parts.path.rstrip('/').rsplit('/', 1)[-1]) if p)
    name, out = open_new(dest, safe_name(stem, 'link') + '.url')
    with out:
        out.write(f'[InternetShortcut]\r\nURL={url}\r\n'.encode())
    mark_as_downloaded(os.path.join(dest, name))
    return name


def outline(value, budget=None):
    """A plist value for the log, with each run of bytes replaced by its
    length; at most a few hundred nodes, however the value is shaped."""
    budget = budget if budget is not None else [400]
    budget[0] -= 1
    if budget[0] < 0:
        return '...'
    if isinstance(value, bytes):
        return f'<{len(value)} bytes>'
    if isinstance(value, dict):
        return {str(key): outline(item, budget) for key, item in list(value.items())[:64]}
    if isinstance(value, list):
        return [outline(item, budget) for item in value[:64]]
    if isinstance(value, str) and len(value) > 200:
        return value[:200] + '...'
    return value
