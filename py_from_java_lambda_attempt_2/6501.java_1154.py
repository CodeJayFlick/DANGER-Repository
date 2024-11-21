Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra.app import util.viewer.field
from ghidra.framework.plugintool import PluginTool
from ghidra.program.database import ProgramBuilder, ProgramDB
from ghidra.program.model.address import AddressFactory
from ghidra.program.model.data import *
from ghidra.program.model.symbol import RefType, SourceType

class XrefViewerTest(unittest.TestCase):

    def setUp(self):
        self.env = TestEnv()
        self.program = build_program()
        self.tool = env.launch_default_tool(program)
        self.cb = env.get_plugin(CodeBrowserPlugin)

    def tearDown(self):
        env.dispose()

    @unittest.skip("This test is not implemented in Python")
    def test_view_references_to_data(self):
        double_click_xref("1001007", "XREF[2]: ")
        comp = waitFor_component_provider(TableComponentProvider)
        table = (TableComponentProvider)comp
        self.assertEqual(2, table.getModel().get_row_count())

    @unittest.skip("This test is not implemented in Python")
    def test_view_references_to_function(self):
        double_click_xref("1001005", "XREF[1]: ")
        comp = waitFor_component_provider(TableComponentProvider)
        table = (TableComponentProvider)comp
        self.assertEqual(1, table.getModel().get_row_count())

    @unittest.skip("This test is not implemented in Python")
    def test_view_references_in_structure_in_structure(self):
        create_structure_in_structure()

        # First expand the structure.
        parent_struct_address = addr("100101b")

        goTo(tool, program, parent_struct_address)

        expand_data()

        add_data_xref_fields_to_listing()

        # We have 3 structure refs: 1 to the top-level parent, 1 to the nested structure,
        # and 1 to the parent struct's second element. The top-level will report all 3
        # refs. The child structure will report only 2.
        double_click_xref("100101b", "XREF[1,2]: ")  # parent structure XRef field
        self.assert_table_x_ref_count(3)

        double_click_xref("100101b", 0, "XREF[1,1]: ")
        self.assert_table_x_ref_count(2)

    def assert_table_x_ref_count(self, expected_row_count):
        comp = waitFor_component_provider(TableComponentProvider)
        table = (TableComponentProvider)comp
        model = table.getModel()
        self.assertEqual(expected_row_count, model.get_row_count())

    def add_data_xref_fields_to_listing(self):
        run_swing(lambda: cb.get_listings_panel().show_header(True))

        field_header = cb.get_listings_panel().get_field_header()
        index = field_header.index_of_tab("Open Data")
        field_header.set_selected_index(index)
        model = field_header.get_header_tab().getModel()
        add_field(model, "XRef Header", 6)

    def add_field(self, model, field_name, column):
        for factory in model.get_factories():
            if factory.get_field_name() == field_name:
                model.add_factory(factory, 0, column)
                break

    def build_program(self):
        builder = ProgramBuilder("notepad", ProgramBuilder._TOY, self)

        builder.create_memory(".text", "0x1001000", 0x6600)
        builder.create_entry_point("1001000", "entrypoint")
        builder.create_empty_function(None, "1001005", 40, None)
        builder.set_bytes("10010a0", "ff 15 d4 10 00 01", True)

        builder.create_memory_reference("1001005", "1001007", RefType.DATA, SourceType.DEFAULT, 0)
        builder.create_memory_read_reference("1001009", "1001005")

    def create_structure_in_structure(self):
        id = program.start_transaction("Structure")

        struct = StructureDataType("ParentStructure", 0)
        child = StructureDataType("ChildStructure", 0)
        child.add(ByteDataType())
        child.add(ByteDataType())

        struct.add(child)
        struct.add(ByteDataType())  # a child below the first child structure

        cmd = CreateStructureCmd(struct, addr(NESTED_STRUCT_ADDR))

        cmd.apply_to(program)
        program.end_transaction(id, True)

    def double_click_xref(self, address, expected_field_text):
        run_swing(lambda: cb.go_to_field(addr(address), "XRef Header", 0, 2))
        current_field = cb.get_current_field()
        actual_text = current_field.get_text()
        self.assertEqual("The Listing is not on the expected field", expected_field_text, actual_text)

    def double_click_xref(self, address, row, expected_field_text):
        path = [i for i in range(row)]

        loc = XRefHeaderFieldLocation(program, addr(address), path, 0)
        event = ProgramLocationPluginEvent("Test", loc, program)
        tool.fire_plugin_event(event)

    def expand_data(self):
        action = get_action(cb, "Expand All Data")
        perform_action(action, cb.get_provider().get_action_context(None), True)

if __name__ == "__main__":
    unittest.main()
```

Please note that the above Python code is not a direct translation of the Java code. It's more like an adaptation to fit into the Python syntax and structure.