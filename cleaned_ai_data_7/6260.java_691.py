import unittest
from ghidra_app.plugin.core.checksums import ComputeChecksumsPlugin
from ghidra_framework.plugintool import PluginTool
from ghidra_program.database import ProgramBuilder, AddressSpace
from ghidra_program.model.address import Address

class TestComputeChecksums(unittest.TestCase):

    def setUp(self):
        self.env = None
        self.tool = None
        self.plugin = None
        self.program = None
        self.show_provider_action = None
        self.compute_action = None
        self.hex_action = None
        self.selection_action = None
        self.ones_comp_action = None
        self.twos_comp_action = None

    def testActionEnablement(self):
        # Set up the environment and plugin
        self.env = TestEnv()
        self.tool = self.env.get_tool()
        configure_tool(self.tool)

        open_program()

        # Enable or disable actions as needed
        assertTrue(show_provider_action.isEnabled())
        perform_action(show_provider_action, True)
        assertTrue(show_provider_action.isEnabled())

    def testBasicChecksums(self):
        model = setup_model_for_entire_program()
        toggle_hex(False)

        checksum8 = model.get_checksum("Checksum-8")
        checksum16 = model.get_checksum("Checksum-16")
        checksum32 = model.get_checksum("Checksum-32")

        # Perform checks and assertions
    def testCrcAndAdler(self):
        model = setup_model_for_entire_program()
        toggle_hex(False)

        adler32 = model.get_checksum("Adler-32")
        crc16 = model.get_checksum("CRC-16")
        ccitt = model.get_checksum("CRC-16-CCITT")
        crc32 = model.get_checksum("CRC-32")

    def testToggleSelection(self):
        # Set up the environment and plugin
        self.env = TestEnv()
        self.tool = self.env.get_tool()

        open_program()

        # Enable or disable actions as needed
        set_selected(selection_action, False)
        waitForTasks()

    def testUninitialized(self):
        setup_model_for_selection("0x01002ffc", "0x01008003")

        provider = get_provider()
        error = provider.getErrorStatus()
        assertTrue(error.contains("contains uninitialized memory"))

        addr = "0x01001000"
        goTo(addr)
        select(addr, addr)
        error = provider.getErrorStatus()
        assertTrue(error.isEmpty())

    def testShaAndMd(self):
        model = setup_model_for_entire_program()

        md2 = model.get_checksum("MD2")
        md5 = model.get_checksum("MD5")
        sha1 = model.get_checksum("SHA-1")

    # Helper functions
    def open_program(self):
        program = build_program("sample")
        self.env.show_tool(program)
        waitForSwing()

    def configure_tool(self, tool_to_configure):
        tool_to_configure.add_plugin(BlockModelServicePlugin.class.getName())
        tool_to_configure.add_plugin(NextPrevAddressPlugin.class.getName())
        tool_to_configure.add_plugin(CodeBrowserPlugin.class.getName())
        tool_to_configure.add_plugin(GoToAddressLabelPlugin.class.getName())

    def get_checksum_result(self, model, alg):
        return str(model.getColumnValueForRow(alg, ChecksumTableModel.VALUE_COL))

    def select_ones_complement(self, selected):
        set_selected(ones_comp_action, selected)

    def select_twos_complement(self, selected):
        set_selected(twos_comp_action, selected)

    def toggle_hex(self, selected):
        set_selected(hex_action, selected)

    # Helper classes
class TestEnv:
    def get_tool(self):
        return None

    def show_tool(self, program):
        pass

    def dispose(self):
        pass

if __name__ == "__main__":
    unittest.main()
