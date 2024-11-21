import unittest
from ghidra_app_plugin import CodeBrowserPlugin
from ghidra_framework_plugintool import PluginTool
from ghidra_program_model_address import AddressFactory
from ghidra_program_model_data import Data, DataType
from ghidra_program_model_listing import ListingModel

class ExpandCollapseDataActionsTest(unittest.TestCase):
    def setUp(self):
        self.env = TestEnv()
        tool = self.env.get_tool()
        tool.add_plugin(CodeBrowserPlugin())
        
        program = build_program()
        pm = tool.get_service(ProgramManager)
        pm.open_program(program.get_domain_file())
        addr_factory = program.get_address_factory()
        self.env.show_tool()
        provider = code_viewer_provider(tool, "Listing")
        listing_model = provider.get_listing_panel().get_listing_model()

    def tearDown(self):
        if self.program is not None:
            self.program.release(self)
        self.env.dispose()

    def test_toggle_top_level(self):
        addr = addr(STRUCT_1)
        assert_data_closed(addr)
        perform_action(toggle_expand, get_context(addr), True)
        assert_data_open(addr)

    # ... and so on for the rest of the tests

def build_program():
    builder = ToyProgramBuilder("Test", True, None)
    struct = create_structure()
    builder.apply_data_type(STRUCT_1, struct)
    return builder.get_program()

def create_structure():
    struct2 = StructureDataType("inner2", 0)

    for _ in range(10):
        struct2.add(ByteDataType())

    struct1 = StructureDataType("inner1", 0)

    for _ in range(10):
        struct1.add(ByteDataType())
    struct1.add(struct2)

    return StructureDataType("Struct", 0).add(struct1).add(ByteDataType() * 10).add(struct1)

def addr(offset):
    return AddressFactory().get_default_address_space().get_address(offset)

# ... and so on for the rest of the functions

if __name__ == "__main__":
    unittest.main()
