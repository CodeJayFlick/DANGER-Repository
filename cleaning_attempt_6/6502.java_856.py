import unittest
from ghidra.app.plugin.core.codebrowser import CodeBrowserPlugin
from ghidra.framework.options import Options
from ghidra.program.model.address import AddressFactory
from ghidra.program.model.data import PointerDataType
from ghidra.program.model.listing import ListingModel

class TestListingPanel(unittest.TestCase):
    def setUp(self):
        self.env = None
        self.tool = None
        self.cb = None
        self.program = None
        self.addr_factory = None
        self.space = None
        self.cvs = None
        self.listing_model = None

    def test_get_layout(self):
        assert not get_layout(addr(0))
        layout = get_layout(addr(0x1001000))
        assert layout is not None
        self.assertEqual(6, len(layout.get_fields()))

        assert not get_layout(addr(0x1001001))

    def test_get_strings_from_layout(self):
        env.show_tool()
        layout = get_layout(addr(0x1001008))

        n = layout.get_num_fields()
        self.assertEqual(7, n)

        self.assertEqual("ADVAPI32.dll_RegQueryValueExW", layout.get_field(0).get_text())
        self.assertEqual("XREF[1]:  ", layout.get_field(1).get_text())
        self.assertEqual("01001100(R)   ", layout.get_field(2).get_text())
        self.assertEqual("01001008", layout.get_field(3).get_text())
        self.assertEqual("01 02 03 04", layout.get_field(4).get_text())
        self.assertEqual("addr", layout.get_field(5).get_text())
        self.assertEqual("ADVAPI32.dll::RegQueryValueExW", layout.get_field(6).get_text())

    def test_get_strings_from_layout1(self):
        env.show_tool()
        layout = get_layout(addr(0x1004772))

        n = layout.get_num_fields()
        self.assertEqual(4, n)

        self.assertEqual("01004772", layout.get_field(0).get_text())
        self.assertEqual("bf 00 01 00 00", layout.get_field(1).get_text())
        self.assertEqual("MOV", layout.get_field(2).get_text())
        self.assertEqual("EDI,0x100", layout.get_field(3).get_text())

    def test_program_location(self):
        f = (layout.get_fields())[1]
        self.assertEqual("bf 00 01 00 00", f.get_text())

        ff = f.get_factory()
        rc = f.text_offset_to_screen_location(3)
        loc = ff.get_program_location(rc.row(), rc.col(), f)

        self.assertIsInstance(loc, BytesFieldLocation)
        bfloc = (BytesFieldLocation) loc
        self.assertEqual(1, bfloc.byte_index())

    def test_program_location2(self):
        id = program.start_transaction("test")
        inst = program.get_listing().get_instruction_at(addr(0x1004772))
        comment = "This is a very long comment. I want this sentence to wrap to the next line so that I can test wrapping."
        inst.set_comment(comment)
        program.end_transaction(id, True)

    def test_program_location3(self):
        id = program.start_transaction("test")
        inst = program.get_listing().get_instruction_at(addr(0x1004772))
        comment1 = "This is a very long comment."
        comment2 = "I want this sentence to wrap to the next line so that I can test wrapping."
        comments = [comment1, comment2]
        inst.set_comment_as_array(comments)
        program.end_transaction(id, True)

    def test_text_offset(self):
        id = program.start_transaction("test")
        inst = program.get_listing().get_instruction_at(addr(0x1004772))
        comment1 = "This is a very long comment."
        comment2 = "I want this sentence to wrap to the next line so that I can test wrapping."
        comments = [comment1, comment2]
        inst.set_comment_as_array(comments)
        program.end_transaction(id, True)

    def test_listing_display_listener(self):
        show_tool(tool)

        addresses = AtomicReference()
        cvs.add_listening_display_listener(AddressSetDisplayListener())
        assert not addresses.get()

        cvs.go_to(ProgramLocation(program, addr(0x1008000)), False)
        assert not addresses.get().contains(addr(0x1001000))

    def reset_format_options(self):
        field_options = cb.get_format_manager().get_field_options()
        names = [name for name in field_options.get_option_names() if not name.startswith("Format Code")]
        for name in names:
            if "Show" in name or "Flag" in name:
                field_options.set_boolean(name, False)
            elif "Lines" in name:
                field_options.set_int(name, 0)

    def addr(self, address):
        return self.addr_factory.get_address(address)

def get_layout(addr):
    return listing_model.get_layout(addr, False)

if __name__ == "__main__":
    unittest.main()
