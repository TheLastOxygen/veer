# SPDX-License-Identifier: MIT
import gzip
import io
import os
import tempfile
import unittest
import zlib

from veer import archive, transfer


def build(members):
    """A portable CPIO archive of (name, data) files, after a '.' folder."""
    pieces = [('.', archive.DIRECTORY_MODE, 0, 0, ())]
    pieces += [(name, archive.FILE_MODE, len(data), 0, (data,)) for name, data in members]
    return b''.join(archive.write_archive(pieces))


def newc(members):
    """A 'new ASCII' (070701) archive, as some Apple senders write."""
    out = b''
    for number, (name, data) in enumerate(members + [('TRAILER!!!', b'')], start=1):
        raw = name.encode() + b'\0'
        mode = 0 if name == 'TRAILER!!!' else archive.FILE_MODE
        fields = [number, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(raw), 0]
        header = b'070701' + b''.join(b'%08x' % f for f in fields) + raw
        out += header + b'\0' * (-len(header) % 4) + data + b'\0' * (-len(data) % 4)
    return out + b'\0' * (-len(out) % 512)


class CpioTest(unittest.TestCase):
    def test_round_trip(self):
        data = build([('./a.txt', b'hello'), ('./b.bin', os.urandom(70_000))])
        entries = [(e.pathname, e.isfile, b''.join(e.blocks()))
                   for e in archive.read_entries(io.BytesIO(data))]
        self.assertEqual([e[0] for e in entries], ['.', './a.txt', './b.bin'])
        self.assertEqual(entries[1][2], b'hello')
        self.assertFalse(entries[0][1])

    def test_archive_length_matches(self):
        files = [('./a.txt', b'hello'), ('./b', b'x' * 1000)]
        self.assertEqual(len(build(files)),
                         archive.archive_length([('.', 0)] + [(n, len(d)) for n, d in files]))
        self.assertEqual(len(build(files)) % archive.RECORD_BYTES, 0)

    def test_reads_new_ascii(self):
        entries = [(e.pathname, b''.join(e.blocks()))
                   for e in archive.read_entries(io.BytesIO(newc([('x.txt', b'abc')])))]
        self.assertEqual(entries, [('x.txt', b'abc')])

    def test_truncated_archive_is_an_error(self):
        data = build([('./a.txt', b'hello')])
        with self.assertRaises(archive.CpioError):
            for entry in archive.read_entries(io.BytesIO(data[:80])):
                b''.join(entry.blocks())

    def test_file_that_changes_size_is_refused(self):
        members = [('./a', archive.FILE_MODE, 10, 0, (b'short',))]
        with self.assertRaises(archive.CpioError):
            b''.join(archive.write_archive(members))

    def test_trailer_scanner_spots_the_end(self):
        data = build([('./a.txt', b'hello' * 300)])
        scanner = archive.TrailerScanner()
        for i in range(0, len(data) - 1, 7):
            scanner.feed(data[i:min(i + 7, len(data) - 1)])
            self.assertFalse(scanner.complete)
        scanner.feed(data[-1:])
        self.assertTrue(scanner.complete)


class DvzipTest(unittest.TestCase):
    def decode(self, body):
        out = io.BytesIO()
        transfer.decode_upload(io.BytesIO(body), out, 10 * transfer.MIB)
        return out.getvalue()

    def test_round_trip_compressible_and_not(self):
        plain = build([('./zeros', b'\0' * 50_000), ('./noise', os.urandom(50_000))])
        body = b''.join(archive.encode_dvzip([plain]))
        self.assertEqual(self.decode(body), plain)

    def test_gzip_body(self):
        plain = build([('./a', b'abc')])
        self.assertEqual(self.decode(gzip.compress(plain)), plain)

    def test_decompression_bomb_is_stopped(self):
        bomb = zlib.compress(b'\0' * (5 * transfer.MIB))
        body = len(bomb).to_bytes(4, 'big') + bomb
        with self.assertRaises(transfer.UploadLimitError):
            transfer.decode_upload(io.BytesIO(body), io.BytesIO(), transfer.MIB)

    def test_end_watcher_sees_a_complete_archive_in_pieces(self):
        plain = build([('./a', os.urandom(40_000))])
        body = b''.join(archive.encode_dvzip([plain]))
        watcher = archive.ArchiveEndWatcher()
        results = [watcher.feed(body[i:i + 1000]) for i in range(0, len(body), 1000)]
        self.assertTrue(results[-1])
        self.assertFalse(any(results[:-1]))

    def test_end_watcher_gives_up_on_garbage(self):
        watcher = archive.ArchiveEndWatcher()
        self.assertFalse(watcher.feed(b'\x00\x00\x00\x05hello'))
        self.assertTrue(watcher.gave_up)


class NameTest(unittest.TestCase):
    def test_unsafe_names(self):
        cases = {
            '../../evil.exe': 'evil.exe',
            'C:\\Windows\\x.dll': 'x.dll',
            'photo.jpg:stream': 'photo.jpgstream',
            'con.txt': '_con.txt',
            'LPT1': '_LPT1',
            'gpj.\u202eexe': 'gpj.exe',
            'trailing. . ': 'trailing',
            '.hidden': 'hidden',
            '...': 'fallback',
            'caf\u0065\u0301.txt': 'caf\u00e9.txt',
        }
        for given, expected in cases.items():
            self.assertEqual(transfer.safe_name(given, 'fallback'), expected, given)

    def test_long_name_is_cut_keeping_extension(self):
        name = transfer.safe_name('a' * 400 + '.jpg', 'x')
        self.assertTrue(name.endswith('.jpg'))
        self.assertLessEqual(len(name), transfer.MAX_NAME_UNITS)


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.dest = self.dir.name

    def store(self, plain):
        raw = tempfile.TemporaryFile(dir=self.dest)
        self.addCleanup(raw.close)
        raw.write(b''.join(archive.encode_dvzip([plain])))
        return transfer.store_upload(raw, self.dest, 't', transfer.ReceiveBudget(self.dest, 50))

    def test_files_are_stored_flat_and_marked(self):
        names = self.store(build([('./a.txt', b'one'), ('./sub/../../b.txt', b'two'),
                                  ('./._a.txt', b'finder junk')]))
        self.assertEqual(names, ['a.txt', 'b.txt'])
        with open(os.path.join(self.dest, 'b.txt'), 'rb') as f:
            self.assertEqual(f.read(), b'two')
        if os.name == 'nt':
            with open(os.path.join(self.dest, 'a.txt:Zone.Identifier'), 'rb') as f:
                self.assertIn(b'ZoneId=3', f.read())

    def test_existing_file_is_not_overwritten(self):
        with open(os.path.join(self.dest, 'a.txt'), 'wb') as f:
            f.write(b'mine')
        self.assertEqual(self.store(build([('./a.txt', b'theirs')])), ['a-1.txt'])
        with open(os.path.join(self.dest, 'a.txt'), 'rb') as f:
            self.assertEqual(f.read(), b'mine')

    def test_failure_removes_partial_output(self):
        plain = build([('./a.txt', b'one'), ('./b.txt', b'two')])
        with self.assertRaises(archive.CpioError):
            self.store(plain[:-600])
        # Only the test's own still-open wire file may be left.
        self.assertFalse({'a.txt', 'b.txt'} & set(os.listdir(self.dest)))

    def test_too_many_members(self):
        plain = build([(f'./{i}', b'') for i in range(transfer.MAX_ARCHIVE_MEMBERS + 1)])
        with self.assertRaises(transfer.UploadLimitError):
            self.store(plain)

    def test_live_photo_pair_shares_a_stem(self):
        names = self.store(build([('./IMG.pvt/IMG.HEIC', b'still'), ('./IMG.pvt/IMG.MOV', b'video'),
                                  ('./IMG.pvt/metadata.plist', b'x')]))
        self.assertEqual(names, ['IMG.HEIC', 'IMG.MOV'])

    def test_link_is_stored_inert(self):
        name = transfer.store_link('https://example.com/page', self.dest)
        with open(os.path.join(self.dest, name), 'rb') as f:
            self.assertEqual(f.read(), b'[InternetShortcut]\r\nURL=https://example.com/page\r\n')
        self.assertFalse(transfer.is_web_link('https://x/\r\nIconFile=\\\\evil\\share'))
        self.assertFalse(transfer.is_web_link('file:///C:/Windows'))


class BodyTest(unittest.TestCase):
    def read(self, raw, headers, limit=1000):
        return transfer.read_small_body(io.BufferedReader(io.BytesIO(raw)), headers, limit)

    def test_chunked(self):
        self.assertEqual(self.read(b'3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n',
                                   {'Transfer-Encoding': 'chunked'}), b'abcde')

    def test_content_length(self):
        self.assertEqual(self.read(b'hello', {'Content-Length': '5'}), b'hello')

    def test_too_large(self):
        with self.assertRaises(transfer.BodyTooLarge):
            self.read(b'x' * 20, {'Content-Length': '20'}, limit=10)
        with self.assertRaises(transfer.BodyTooLarge):
            self.read(b'14\r\n' + b'x' * 20 + b'\r\n0\r\n\r\n', {'Transfer-Encoding': 'chunked'},
                      limit=10)

    def test_bad_framing(self):
        for raw, headers in ((b'zz\r\n', {'Transfer-Encoding': 'chunked'}),
                             (b'', {'Transfer-Encoding': 'gzip'}),
                             (b'', {}),
                             (b'abc', {'Content-Length': '-1'})):
            with self.assertRaises(transfer.RequestBodyError):
                self.read(raw, headers)


if __name__ == '__main__':
    unittest.main()
