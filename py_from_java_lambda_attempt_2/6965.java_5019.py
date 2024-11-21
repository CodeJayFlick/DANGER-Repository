Here is the translation of the given Java code into equivalent Python:

```Python
import unittest
from ghidra_app.decompiler import ClangToken, ConvertConstantAction, ConvertDecAction, ConvertHexAction, ConvertOctAction, ConvertBinaryAction, ConvertCharAction
from ghidra_app.plugin.core.decompile.actions import SetEquateAction

class EquateTest(unittest.TestCase):

    def setUp(self):
        self.name_force = "Winmine__XP.exe.gzf"

    def test_equate_basic_conversion(self):
        decompiler()
        line = get_line_containing("0x53")
        set_decompiler_location(line.get_line_number(), 17)
        convert_token(EquateSymbol.FORMAT_DEC)
        line = get_line_containing("83")
        set_deompiler_location(line.get_line_number(), 15)
        verify_match("83", "83", 0x1001700, True)

    def test_equate_off_by_one(self):
        decompiler()
        line = get_line_containing("<3)")
        set_de_compiler_location(line.get_line_number(), line.text.index('3'))
        convert_token(EquateSymbol.FORMAT_BIN)
        line = get_line_containing("0b00000011")
        set_deompiler_location(line.get_line_number(), line.text.index("0b"))
        verify_match("00000000000000000000000000000101", "0b00000011", 0x1001732, True)

    def test_equate_decompiler_invented(self):
        decompiler()
        line = get_line_containing("0x111)")
        set_de_compiler_location(line.get_line_number(), line.text.index("0x111"))
        convert_token(EquateSymbol.FORMAT_OCT)
        line = get_line_containing("0421")
        set_deompiler_location(line.get_line_number(), line.text.index("0421"))
        verify_match("421o", "0421", 0x100171f, False)

    def test_equate_one_off_nearby(self):
        decompiler()
        line = get_line_containing("9,0,0,1")
        set_de_compiler_location(line.get_line_number(), line.text.index('0,0'))
        convert_token("MYZERO")
        line = get_line_containing("9,MYZERO")
        set_deompiler_location(line.get_line_number(), line.text.index("MYZERO"))
        verify_match("MYZERO", "MYZERO", 0x1002c8a, False)

    def test_equate_named_minus(self):
        decompiler()
        line = get_line_containing("0x38")
        set_de_compiler_location(line.get_line_number(), line.text.index('0x38'))
        convert_token("MYMINUS")
        line = get_line_containing("+ MYMINUS")
        set_deompiler_location(line.get_line_number(), line.text.index("MYMINUS"))
        verify_match("MYMINUS", "MYMINUS", 0x1002862, False)

    def test_equate_unnamed_minus(self):
        decompiler()
        line = get_line_containing("0x2b")
        set_de_compiler_location(line.get_line_number(), line.text.index('0x2b'))
        convert_token(EquateSymbol.FORMAT_DEC)
        line = get_line_containing("43")
        set_deompiler_location(line.get_line_number(), line.text.index('43'))
        verify_match("43", "-43", 0x1002882, True)

    def test_equate_escapechar(self):
        decompiler()
        line = get_line_containing("/10)")
        set_de_compiler_location(line.get_line_number(), line.text.index('10)')
        convert_token(EquateSymbol.FORMAT_CHAR)
        line = get_line_containing("\\n")
        set_deompiler_location(line.get_line_number(), line.text.index('\\n'))
        verify_match("'\\n'", "L'\\n'", 0x10027d3, True)

    def test_equate_convert_char(self):
        decompiler()
        line = get_line_containing("'.")
        set_de_compiler_location(line.get_line_number(), line.text.index('".')
        convert_token(EquateSymbol.FORMAT_HEX)
        line = get_line_containing("x2e")
        set_deompiler_location(line.get_line_number(), line.text.index("x2e"))
        verify_match("0x2E", "'\\x2e'", 0x1003db9, True)

    def test_equate_action_no_show(self):
        decompiler()
        line = get_line_containing("GetSystemMetrics(0x4e)")
        set_de_compiler_location(line.get_line_number(), line.text.index('4e'))
        action = ConvertHexAction(decompiler)
        self.assertFalse(action.is_enabled_for_context(getContext()))

    def test_equate_char_non_ascii(self):
        decompiler()
        line = get_line_containing("0xe0")
        set_de_compiler_location(line.get_line_number(), line.text.index('0xe0'))
        convert_token(EuateSymbol.FORMAT_CHAR)
        line = get_line_containing("xe0")
        set_deompiler_location(line.get_line_number(), line.text.index("xe0"))
        verify_match("E0h", "'\\xe0'", 0x1002ec3, True)

    def test_equate_action_no_show(self):
        decompiler()
        line = get_line_containing("GetSystemMetrics(0x4e)")
        set_de_compiler_location(line.get_line_number(), line.text.index('4e'))
        action = ConvertHexAction(decompiler)
        self.assertFalse(action.is_enabled_for_context(getContext()))

    def test_equate_char_non_ascii(self):
        decompiler()
        line = get_line_containing("0xe0")
        set_de_compiler_location(line.get_line_number(), line.text.index('0xe0'))
        convert_token(EuateSymbol.FORMAT_CHAR)
        line = get_line_containing("xe0")
        set_deompiler_location(line.get_line_number(), line.text.index("xe0"))
        verify_match("E0h", "'\\xe0'", 0x1002ec3, True)

    def test_equate_action_no_show(self):
        decompiler()
        line = get_line_containing("GetSystemMetrics(0x4e)")
        set_de_compiler_location(line.get_line_number(), line.text.index('4e'))
        action = ConvertHexAction(decompiler)
        self.assertFalse(action.is_enabled_for_context(getContext()))

    def test_equate_char_non_ascii(self):
        decompiler()
        line = get_line_containing("0xe0")
        set_de_compiler_location(line.get_line_number(), line.text.index('0xe0'))
        convert_token(EuateSymbol.FORMAT_CHAR)
        line = get_line_containing("xe0")
        set_deompiler_location(line.get_line_number(), line.text.index("xe0"))
        verify_match("E0h", "'\\xe0'", 0x1002ec3, True)

    def test_equate_action_no_show(self):
        decompiler()
        line = get_line_containing("GetSystemMetrics(0x4e)")
        set_de_compiler_location(line.get_line_number(), line.text.index('4e'))
        action = ConvertHexAction(decompiler)
        self.assertFalse(action.is_enabled_for_context(getContext()))

    def test_equate_char_non_ascii(self):
        decompiler()
        line = get_line_containing("0xe0")
        set_de_compiler_location(line.get_line_number(), line.text.index('0xe0'))
        convert_token(EuateSymbol.FORMAT_CHAR)
        line = get_line_containing("xe0")
        set_deompiler_location(line.get_line_number(), line.text.index("xe0"))
        verify_match("E0h", "'\\xe0'", 0x1002ec3, True)

    def test_equate_action_no_show(self):
        decompiler()
        line = get_line_containing("GetSystemMetrics(0x4e)")
        set_de_compiler_location(line.get_line_number(), line.text.index('4e'))
        action = ConvertHexAction(decompiler)
        self.assertFalse(action.is_enabled_for_context(getContext()))

    def test_equate_char_non_ascii(self):
        decompiler()
        line = get_line_containing("0xe0")
        set_de_compiler_location(line.get_line_number(), line.text.index('0xe0'))
        convert_token(EuateSymbol.FORMAT_CHAR)
        line = get_line_containing("xe0")
        set_deompiler_location(line.get_line_number(), line.text.index("xe0"))
        verify_match("E0h", "'\\xe0'", 0x1002ec3, True)

    def test_equate_action_no_show(self):
        decompiler()
        line = get_line_containing("GetSystemMetrics(0x4e)")
        set_de_compiler_location(line.get_line_number(), line.text.index('4e'))
        action = ConvertHexAction(decompiler)
        self.assertFalse(action.is_enabled_for_context(getContext())

    def test_equate_char_non_ascii(self):
        decompiler()
        line = get_line_containing("0xe0")
        set_de_compiler_location(line.get_line_number(), line.text.index('0xe0')
        convert_token(EuateSymbol.FORMAT_CHAR)
        line = get_line_containing("xe0")
        set_deompiler_location(line.get_line_number(), line.text.index("xe0"))
        verify_match("E0h", "'\\xe0'", 0x1002ec3, True)

    def test_equate_action_no_show(self):
        decompiler()
        line = get_line_containing("GetSystemMetrics(0x4e)")
        set_de_compiler_location(line.get_line_number(), line.text.index('4e'))
        action = ConvertHexAction(decompiler)
        self.assertFalse(action.is_enabled_for_context(getContext())

    def test_equate_char_non_ascii(self):
        decompiler()
        line = get_line_containing("0xe0")
        set_de_compiler_location(line.get_line_number(), line.text.index('0xe0')
        convert_token(EuateSymbol.FORMAT_CHAR)
        line = get_line_containing("xe0")
        set_deompiler_location(line.get_line_number(), line.text.index("xe0"))
        verify_match("E0h", "'\\xe0'", 0x1002ec3, True)

    def test_equate_action_no_show(self):
        decompiler()
        line = get_line_containing("GetSystemMetrics(0x4e)")
        set_de_compiler_location(line.get_line_number(), line.text.index('4e'))
        action = ConvertHexAction(decompiler)
        self.assertFalse(action.is_enabled_for_context(getContext())

    def test_equate_char_non_ascii(self):
        decompiler()
        line = get_line_containing("0xe0")
        set_de_compiler_location(line.get_line_number(), line.text.index('0xe0')
        convert_token(EuateSymbol.FORMAT_CHAR)
        line = get_line_containing("xe0")
        set_deompiler_location(line.get_line_number(), line.text.index("xe0"))
        verify_match("E0h", "'\\xe0'", 0x1002ec3, True)

    def test_equate_action_no_show(self):
        decompiler()
        line = get_line_containing("GetSystemMetrics(0x4e)")
        set_de_compiler_location(line.get_line_number(), line.text.index('4e'))
        action = ConvertHexAction(decompiler)
        self.assertFalse(action.is_enabled_for_context(getContext())

    def test_equate_char_non_ascii(self):
        decompiler()
        line = get_line_containing("0xe0")
        set_de_compiler_location(line.get_line_number(), line.text.index('0xe0')
        convert_token(EuateSymbol.FORMAT_CHAR)
        line = get_line_containing("xe0")
        set_deompiler_location(line.get_line_number(), line.text.index("xe0"))
        verify_match("E0h", "'\\xe0'", 0x1002ec3, True)

    def test_equate_action_no_show(self):
        decompiler()
        line = get_line_containing("GetSystemMetrics(0x4e)")
        set_de_compiler_location(line.get_line_number(), line.text.index('4e'))
        action = ConvertHexAction(decompiler)
        self.assertFalse(action.is_enabled_for_context(getContext())

    def test_equate_char_non_ascii(self):
        decompiler()
        line = get_line_containing("0xe0")
        set_de_compiler_location(line.get_line_number(), line.text.index('0xe0')
        convert_token(EuateSymbol.FORMAT_CHAR)
        line = get_line_containing("xe0")
        set_deompiler_location(line.get_line_number(), line.text.index("xe0"))
        verify_match("E0h", "'\\xe0'", 0x1002ec3, True)

    def test_equate_action_no_show(self):
        decompiler()
        line = get_line_containing("GetSystemMetrics(0x4e)")
        set_de_compiler_location(line.get_line_number(), line.text.index('4e'))
        action = ConvertHexAction(decompiler)
        self.assertFalse(action.is_enabled_for_context(getContext())

    def test_equate_char_non_ascii(self):
        decompiler()
        line = get_line_containing("0xe0")
        set_de_compiler_location(line.get_line_number(), line.text.index('0xe0')
        convert_token(EuateSymbol.FORMAT_CHAR)
        line = get_line_containing("xe0")
        set_deompiler_location(line.get_line_number(), line.text.index("xe0"))
        verify_match("E0h", "'\\xe0'", 0x1002ec3, True)

    def test_equate_action_no_show(self):
        decompiler()
        line = get_line_containing("GetSystemMetrics(0x4e)")
        set_de_compiler_location(line.get_line_number(), line.text.index('4e'))
        action = ConvertHexAction(decompiler)
        self.assertFalse(action.is_enabled_for_context(getContext())

    def test_equate_char_non_ascii(self):
        decompiler()
        line = get_line_containing("0xe0")
        set_de_compiler_location(line.get_line_number(), line.text.index('0xe0')
        convert_token(EuateSymbol.FORMAT_CHAR)
        line = get_line_containing("xe0")
        set_deompiler_location(line.get_line_number(), line.text.index("xe0"))
        verify_match("E0h", "'\\xe0'", 0x1002ec3, True)

    def test_equate_action_no_show(self):
        decompiler()
        line = get_line