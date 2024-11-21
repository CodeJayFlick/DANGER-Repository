Here is the translation of the given Java code into Python:

```Python
import io
from typing import Any

class CliStreamStrings:
    def __init__(self, csh: Any, offset: int, size: int, br):
        self.csh = csh
        self.offset = offset
        self.size = size
        self.br = br

    def parse(self) -> bool:
        # Your logic here to handle the parsing of CliStreamStrings
        return True  # Assuming it's always true for this example

    def get_string(self, index: int) -> str:
        if index < 0 or index >= len(self.strings):
            return None
        return self.strings[index]

class AbstractGTest:
    pass

def init_cli_stream_strings() -> CliStreamStrings:
    baos = io.BytesIO()
    baos.write(b'\x00\x00\x00\x00')  # offset
    baos.write(b'\x00\x00\x00\x00')  # size
    baos.write(b'a' + b'b' + b'c' + b'\x00')  # name

    pw = io.TextIOWrapper(baos, encoding='utf-8', newline='\n')
    pw.write('\0')
    pw.write('test1\0')
    pw.write('test2\0')
    pw.write('ab\ucC01\u1202ab\0')

    pw.flush()
    size = baos.tell() - 4
    bytes = bytearray(baos.getvalue())

    LittleEndianDataConverter.put_int(bytes, 0, offset := int.from_bytes(baos.read(4), 'little'))
    LittleEndianDataConverter.put_int(bytes, 4, size)

    bap = io.BytesIO(bytes)
    br = BinaryReader(bap, True)

    csh = CliStreamHeader(None, br)
    css = CliStreamStrings(csh, offset, 0, br)

    return css

def init_cli_stream_strings_empty() -> CliStreamStrings:
    baos = io.BytesIO()
    baos.write(b'\x00\x00\x00\x00')  # offset
    baos.write(b'\x00\x00\x00\x00')  # size
    baos.write(b'a' + b'b' + b'c' + b'\x00')  # name

    pw = io.TextIOWrapper(baos, encoding='utf-8', newline='\n')
    pw.write('\0')

    pw.flush()
    size = baos.tell() - 4
    bytes = bytearray(baos.getvalue())

    LittleEndianDataConverter.put_int(bytes, 0, offset := int.from_bytes(baos.read(4), 'little'))
    LittleEndianDataConverter.put_int(bytes, 4, size)

    bap = io.BytesIO(bytes)
    br = BinaryReader(bap, True)

    csh = CliStreamHeader(None, br)
    css = CliStreamStrings(csh, offset, 0, br)

    return css

def init_cli_stream_strings_header_only() -> CliStreamStrings:
    baos = io.BytesIO()
    baos.write(b'\x00\x00\x00\x00')  # offset
    baos.write(b'\x00\x00\x00\x00')  # size
    baos.write(b'a' + b'b' + b'c' + b'\x00')  # name

    pw = io.TextIOWrapper(baos, encoding='utf-8', newline='\n')
    pw.flush()
    size = baos.tell() - 4
    bytes = bytearray(baos.getvalue())

    LittleEndianDataConverter.put_int(bytes, 0, offset := int.from_bytes(baos.read(4), 'little'))
    LittleEndianDataConverter.put_int(bytes, 4, size)

    bap = io.BytesIO(bytes)
    br = BinaryReader(bap, True)

    csh = CliStreamHeader(None, br)
    css = CliStreamStrings(csh, offset, 0, br)

    return css

class TestCliStreamStrings:
    def test_parse(self):
        css = init_cli_stream_strings()
        self.assertEqual(css.parse(), True)

    def test_get_string(self):
        # Test a normally formed blob of UTF-8 strings
        css = init_cli_stream_strings()
        css.parse()

        self.assertIsNone(css.get_string(-1))
        self.assertEqual(css.get_string(0), '')
        self.assertEqual(css.get_string(1), 'test1')
        self.assertEqual(css.get_string(2), 'est1')
        # ...

    def test_get_string_empty(self):
        # Test a blob that only includes the mandatory single
        # NULL string
        css = init_cli_stream_strings_empty()
        css.parse()

        self.assertEqual(css.get_string(0), '')
        self.assertIsNone(css.get_string(1))
        self.assertIsNone(css.get_string(2))

    def test_get_string_header_only(self):
        # Test a blob that for some reason includes the header
        # only and not the mandatory NULL string
        css = init_cli_stream_strings_header_only()
        css.parse()

        self.assertIsNone(css.get_string(0))
        self.assertIsNone(css.get_string(1))
        self.assertIsNone(css.get_string(2))

if __name__ == '__main__':
    test = TestCliStreamStrings()
    test.test_parse()
    test.test_get_string()
    test.test_get_string_empty()
    test.test_get_string_header_only()