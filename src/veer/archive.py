# SPDX-License-Identifier: MIT
# Adapted from airdrop/cpio.py and airdrop/transfer.py in winawdl,
# Copyright (c) 2026 Raphaël Richaud, itself adapted from omdrop,
# Copyright (c) 2026 Brent Kearney.
"""The archive inside an AirDrop upload: a CPIO archive, cut into DVZip
blocks (or, from older senders, gzip-compressed).

Reads the portable ASCII format (magic 070707) and the two "new ASCII"
formats (070701, 070702); writes the portable one, which Macs and iPhones
accept. Nothing here touches the disk; transfer.py bounds and stores."""
import stat
import zlib

TRAILER = 'TRAILER!!!'
MAX_NAME_BYTES = 4096
BLOCK_BYTES = 64 * 1024
MAGIC_BYTES = 6
# Archives are padded with zeros to a multiple of this after the trailer.
RECORD_BYTES = 512
PORTABLE_MAGIC = b'070707'
# The portable format gives a member's size eleven octal digits.
MAX_PORTABLE_BYTES = 8 ** 11 - 1
FILE_MODE = stat.S_IFREG | 0o644
DIRECTORY_MODE = stat.S_IFDIR | 0o755

# What Veer cuts an upload into. A receiver has to take whatever size a
# sender chose, so a small one is the safe one.
DVZIP_BLOCK_BYTES = 16 * 1024
DVZIP_STORED = 0x80000000
DVZIP_HEADER_BYTES = 4
# Photos and videos do not shrink, so a higher level only costs time.
DVZIP_LEVEL = 1
GZIP_MAGIC = b'\x1f\x8b'


class CpioError(ValueError):
    pass


def _number(field, base):
    try:
        return int(field, base)
    except ValueError:
        raise CpioError(f'invalid header field {field!r}') from None


def _portable_fields(rest):
    """mode, name size and file size from the 70 bytes after a 070707 magic."""
    return _number(rest[12:18], 8), _number(rest[53:59], 8), _number(rest[59:70], 8)


def _new_ascii_fields(rest):
    fields = [_number(rest[i:i + 8], 16) for i in range(0, 104, 8)]
    return fields[1], fields[11], fields[6]


class _Format:
    def __init__(self, rest_bytes, fields, alignment):
        self.rest_bytes = rest_bytes
        self.header_bytes = MAGIC_BYTES + rest_bytes
        self.fields = fields
        self.alignment = alignment

    def padding(self, length):
        return -length % self.alignment


FORMATS = {b'070707': _Format(70, _portable_fields, 1),
           b'070701': _Format(104, _new_ascii_fields, 4),
           b'070702': _Format(104, _new_ascii_fields, 4)}


def _format_for(magic):
    if magic not in FORMATS:
        raise CpioError(f'unsupported cpio magic {magic!r}')
    return FORMATS[magic]


def _name_from(raw):
    return raw.rstrip(b'\0').decode('utf-8', 'replace')


def _check_name_bytes(name_bytes):
    if not 0 < name_bytes <= MAX_NAME_BYTES:
        raise CpioError(f'invalid name length {name_bytes}')


def _read_exact(source, size):
    data = source.read(size)
    if len(data) != size:
        raise CpioError(f'truncated archive: wanted {size} bytes, got {len(data)}')
    return data


class Entry:
    """One archive member. Its data must be read before the next entry is
    requested; whatever is left unread is skipped."""

    def __init__(self, source, name, mode, size):
        self.pathname = name
        self.size = size
        self.isfile = stat.S_ISREG(mode)
        self.isdir = stat.S_ISDIR(mode)
        self._source = source
        self._left = size

    def blocks(self):
        while self._left:
            data = _read_exact(self._source, min(self._left, BLOCK_BYTES))
            self._left -= len(data)
            yield data


def read_entries(source):
    """Yield every member of the CPIO archive in `source`, up to its trailer."""
    while True:
        layout = _format_for(_read_exact(source, MAGIC_BYTES))
        mode, name_bytes, size = layout.fields(_read_exact(source, layout.rest_bytes))
        _check_name_bytes(name_bytes)
        name = _name_from(_read_exact(source, name_bytes))
        _read_exact(source, layout.padding(layout.header_bytes + name_bytes))
        if name == TRAILER:
            return
        entry = Entry(source, name, mode, size)
        yield entry
        for _ in entry.blocks():
            pass
        _read_exact(source, layout.padding(size))


def _portable_header(name, number, mode, size, mtime):
    raw = name.encode('utf-8') + b'\0'
    _check_name_bytes(len(raw))
    if size > MAX_PORTABLE_BYTES:
        raise CpioError(f'{name} is too large for a cpio archive')
    # Device, inode, mode, owner, group, links, device type, time, sizes.
    fields = (0, number, mode, 0, 0, 1, 0)
    head = b''.join(b'%06o' % field for field in fields)
    return PORTABLE_MAGIC + head + b'%011o%06o%011o' % (mtime, len(raw), size) + raw


def write_archive(members):
    """Yield a portable archive piece by piece. Each member is its name in
    the archive, its mode, its size, its modification time and its data in
    blocks."""
    written = 0
    for number, (name, mode, size, mtime, blocks) in enumerate(members, start=1):
        header = _portable_header(name, number, mode, size, max(0, int(mtime)))
        written += len(header) + size
        yield header
        left = size
        for block in blocks:
            left -= len(block)
            if left < 0:
                raise CpioError(f'{name} grew while it was read')
            yield block
        if left:
            raise CpioError(f'{name} changed size while it was read')
    trailer = _portable_header(TRAILER, 0, 0, 0, 0)
    yield trailer + b'\0' * (-(written + len(trailer)) % RECORD_BYTES)


def archive_length(members):
    """How many bytes write_archive yields for members of these names and sizes."""
    written = sum(len(_portable_header(name, 0, 0, size, 0)) + size
                  for name, size in members)
    written += len(_portable_header(TRAILER, 0, 0, 0, 0))
    return written + -written % RECORD_BYTES


class TrailerScanner:
    """Follows an archive as it arrives, keeping none of it, to tell when it
    is all there: its trailer read and its last record filled."""

    def __init__(self):
        self._consumed = 0
        self._trailer_seen = False
        self._skip = 0
        self._held = bytearray()
        self._want = MAGIC_BYTES
        self._stage = self._on_magic
        self._layout = None
        self._entry = None

    @property
    def complete(self):
        return self._trailer_seen and self._consumed % RECORD_BYTES == 0

    def feed(self, data):
        self._consumed += len(data)
        view = memoryview(data)
        while len(view) and not self._trailer_seen:
            if self._skip:
                step = min(self._skip, len(view))
                self._skip -= step
                view = view[step:]
                continue
            take = min(self._want - len(self._held), len(view))
            self._held += view[:take]
            view = view[take:]
            if len(self._held) == self._want:
                held = bytes(self._held)
                self._held.clear()
                self._stage(held)

    def _expect(self, size, stage):
        self._want = size
        self._stage = stage

    def _on_magic(self, magic):
        self._layout = _format_for(magic)
        self._expect(self._layout.rest_bytes, self._on_header)

    def _on_header(self, rest):
        _, name_bytes, size = self._layout.fields(rest)
        _check_name_bytes(name_bytes)
        self._entry = (name_bytes, size)
        self._expect(name_bytes, self._on_name)

    def _on_name(self, raw):
        name_bytes, size = self._entry
        if _name_from(raw) == TRAILER:
            self._trailer_seen = True
            return
        layout = self._layout
        self._skip = (layout.padding(layout.header_bytes + name_bytes) + size +
                      layout.padding(size))
        self._expect(MAGIC_BYTES, self._on_magic)


# DVZip.

def _dvzip_block(data):
    packed = zlib.compress(data, DVZIP_LEVEL)
    if len(packed) < len(data):
        return len(packed).to_bytes(DVZIP_HEADER_BYTES, 'big') + packed
    return (len(data) | DVZIP_STORED).to_bytes(DVZIP_HEADER_BYTES, 'big') + data


def encode_dvzip(pieces):
    """Yield the stream in `pieces` as DVZip blocks: a 4-byte big-endian
    length each, whose top bit marks a block stored as is; the others are
    one zlib stream each, used only when that is smaller."""
    held = bytearray()
    for piece in pieces:
        held += piece
        while len(held) >= DVZIP_BLOCK_BYTES:
            yield _dvzip_block(bytes(held[:DVZIP_BLOCK_BYTES]))
            del held[:DVZIP_BLOCK_BYTES]
    if held:
        yield _dvzip_block(bytes(held))


class ArchiveEndWatcher:
    """Decodes an upload as it arrives, keeping none of it, to tell when its
    archive is complete. A body it cannot follow is left to the idle timeout:
    iPhones and Macs do not always end the HTTP body when the archive ends."""

    def __init__(self):
        self._scanner = TrailerScanner()
        self._gave_up = False
        self._feed = self._first_bytes
        self._held = b''
        self._inflater = None
        self._block_left = 0
        self.decoded = 0  # bytes of the archive seen so far

    @property
    def gave_up(self):
        return self._gave_up

    def feed(self, wire):
        """Take the next bytes of the body; True once the archive is whole."""
        if self._gave_up:
            return False
        try:
            self._feed(self._held + wire)
        except (ValueError, zlib.error):
            self._gave_up = True
            return False
        return self._block_left == 0 and self._scanner.complete

    def _first_bytes(self, data):
        if len(data) < 2:
            self._held = data
            return
        self._held = b''
        if data[:2] == GZIP_MAGIC:
            self._inflater = zlib.decompressobj(zlib.MAX_WBITS | 16)
            self._feed = self._inflate
        else:
            self._feed = self._blocks
        self._feed(data)

    def _inflate(self, data):
        while data:
            plain = self._inflater.decompress(data, BLOCK_BYTES)
            self.decoded += len(plain)
            self._scanner.feed(plain)
            data = self._inflater.unconsumed_tail

    def _blocks(self, data):
        view = memoryview(data)
        while len(view):
            if self._block_left == 0:
                if len(view) < DVZIP_HEADER_BYTES:
                    self._held = bytes(view)
                    return
                header = int.from_bytes(view[:DVZIP_HEADER_BYTES], 'big')
                view = view[DVZIP_HEADER_BYTES:]
                self._block_left = header & ~DVZIP_STORED
                self._inflater = None if header & DVZIP_STORED else zlib.decompressobj()
            piece = view[:self._block_left]
            view = view[len(piece):]
            self._block_left -= len(piece)
            if self._inflater:
                self._inflate(bytes(piece))
            else:
                self.decoded += len(piece)
                self._scanner.feed(piece)
        self._held = b''
