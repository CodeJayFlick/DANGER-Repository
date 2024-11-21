import unittest
from ghidra_test import TestEnv, PluginTool, AddressFactory, ProgramManager, ProgramBuilder, WordDataType
from ghidra_framework_plugintool import PluginTool as GhidraPluginTool
from ghidra_program_database import ProgramBuilder as GhidraProgramBuilder

class CodeBrowserNavigationSegmentedAddressTest(unittest.TestCase):
    def setUp(self):
        self.env = TestEnv()
        tool = self.env.get_tool()
        tool.add_plugin('CodeBrowserPlugin')
        tool.add_plugin('NextPrevAddressPlugin')
        tool.add_plugin('LocationReferencesPlugin')
        tool.add_plugin('MarkerManagerPlugin')

        np = self.env.get_plugin('NextPrevAddressPlugin')
        prev_action = get_action(np, 'Previous Location in History')
        clear_history_action = get_action(np, 'Clear History Buffer')
        cb = self.env.get_plugin('CodeBrowserPlugin')
        next_function_action = get_action(cb, 'Go to next function')
        prev_function_action = get_action(cb, 'Go to previous function')

    def tearDown(self):
        self.env.dispose()

    def load_program(self, program_name):
        program = build_program()
        pm = tool.get_service(ProgramManager)
        pm.open_program(program.get_domain_file())
        addr_factory = program.get_address_factory()

    def build_program(self):
        builder = GhidraProgramBuilder('Test', 'X86_16_REAL_MODE')
        builder.create_memory('Seg_0', '1000:0000', 0x32c0)
        builder.create_memory('Seg_1', '132c:0000', 0x9be)
        builder.set_bytes('1000:03ea', b'7e 09')
        builder.disassemble('1000:03ea', 2)

        builder.set_bytes('1000:0154', b'ff 36 84 00')
        builder.disassemble('1000:0154', 4)

        builder.apply_data_type('132c:0084', WordDataType(), 1)
        builder.create_memory_reference('1000:0154', '132c:0084', RefType.DATA, SourceType.ANALYSIS)

        return builder.get_program()

    def test_operand_navigation_in_segmented(self):
        load_program('login')
        env.show_tool()
        unittest.util.waitForPostedSwingRunnables()
        cb.go_to(OperandFieldLocation(program, addr('1000:03ea'), None, None, None, 0, 0))
        self.assertEqual(addr('1000:03ea'), cb.get_current_address())

        click(cb, 2)
        self.assertEqual(addr('1000:3f5'), cb.get_current_address())

        cb.go_to(XRefFieldLocation(program, addr('132c:0084'), None, addr('1000:0154'), 0, 2))
        self.assertEqual(addr('132c:0084'), cb.get_current_address())

        click(cb, 2)
        self.assertEqual(addr('1000:0154'), cb.get_current_address())


if __name__ == '__main__':
    unittest.main()
