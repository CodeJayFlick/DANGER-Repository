import unittest
from io import BytesIO

class CharDataTypesRenderTest(unittest.TestCase):

    def setUp(self):
        self.thai_cs = 'IBM-Thai'

    def testSimpleASCIIChar(self):
        char_dt = {'a': "'a'", "uchar": "'a'", "wchar": "u'0'",
                   "wchar16": "u'0'", "wchar32": "U'0'"}
        for dt, expected in char_dt.items():
            self.assertEqual(eval(f"{dt}.getRepresentation(mb(False, 'a'), newset(), {dt}.getLength())"), expected)

    def testEncodeSimpleASCIIChar(self):
        char_dt = {'char': "'a'", "uchar": "'a'"}
        for dt, expected in char_dt.items():
            with BytesIO() as buffer:
                eval(f"{dt}.encodeRepresentation('{expected}', mb(False), newset(), -1).tofile(buffer)")
                self.assertEqual(list(buffer.getvalue()), bytes('a'))

    def testWideCharsNonAscii(self):
        buf_thai = {'char': 66, "uchar": 0xcc01}
        for dt, value in buf_thai.items():
            if isinstance(value, int):
                expected = f"u'{value:x}'"
            else:
                expected = value
            self.assertEqual(eval(f"{dt}.getRepresentation(mb(False, {value}), newset().set(thai_cs), {dt}.getLength())"), expected)

    def testEncodeWideCharsNonAscii(self):
        char_dt = {'char': 66}
        for dt, value in char_dt.items():
            with BytesIO() as buffer:
                eval(f"{dt}.encodeRepresentation(f"'{value}'", mb(False), newset().set(thai_cs), -1).tofile(buffer)")
                self.assertEqual(list(buffer.getvalue()), bytes([0x44]))

    def testWideCharsNonAscii_EscSeq(self):
        buf_thai = {'char': 66, "uchar": 0xcc01}
        for dt, value in buf_thai.items():
            if isinstance(value, int):
                expected = f"u'\\{value:x}'"
            else:
                expected = value
            self.assertEqual(eval(f"{dt}.getRepresentation(mb(False, {value}), newset().set(thai_cs).set(RENDER_ENUM.ESC_SEQ), {dt}.getLength())"), expected)

    def testEncodeWideCharsNonAscii_EscSeq(self):
        char_dt = {'char': 66}
        for dt, value in char_dt.items():
            with BytesIO() as buffer:
                eval(f"{dt}.encodeRepresentation(f"'\\{value}'", mb(False), newset().set(thai_cs).set(RENDER_ENUM.ESC_SEQ), -1).tofile(buffer)")
                self.assertEqual(list(buffer.getvalue()), bytes([0x44]))

    def testNonAsciiCharset(self):
        result = charDT.getRepresentation(mb(False, 73), newset().set('IBM-Thai'), charDT.getLength())
        self.assertEqual(result, "'['")

    def testEncodeNonAsciiCharset(self):
        with BytesIO() as buffer:
            charDT.encodeRepresentation("'[]'", mb(False), newset().set('IBM-Thai'), -1).tofile(buffer)
            self.assertEqual(list(buffer.getvalue()), bytes([73]))

    def testEscapeSequenceRender_singlebyte_to_multibyte(self):
        result = charDT.getRepresentation(mb(False, 66), newset().set(thai_cs).set(RENDER_ENUM.ESC_SEQ), charDT.getLength())
        self.assertContainsStr("'\\u0E01'", result)

    def testRender_invalid_values(self):
        buf8 = {'char': 85}
        for dt, value in buf8.items():
            if isinstance(value, int):
                expected = f"{value:x}"
            else:
                expected = "'85h'"
            self.assertEqual(eval(f"{dt}.getRepresentation(mb(False, {value}), newset(), {dt}.getLength())"), expected)

    def testEscapeSequenceRender_literal_unicode_replacement_char(self):
        result = wchar16DT.getRepresentation(mb(False, 0xfd, 0xff), newset(), wchar16DT.getLength())
        self.assertEqual(result, "u'\ufffd'")

        result = wchar16DT.getRepresentation(mb(False, 0xfd, 0xff), newset().set(RENDER_ENUM.ESC_SEQ), wchar16DT.getLength())
        self.assertEqual(result, "u'\\ufffd'")

    def testEncodeByteSequence(self):
        with BytesIO() as buffer:
            charDT.encodeRepresentation("AAh,FFh,FDh", mb(True), newset(), -1).tofile(buffer)
            self.assertEqual(list(buffer.getvalue()), bytes([0xaa, 0xff, 0xfd]))

if __name__ == '__main__':
    unittest.main()
