import unittest
from ghidra_app_plugin_core_codebrowser import CodeBrowserPlugin
from ghidra_framework_plugintool import PluginTool
from ghidra_program_database import ProgramBuilder
from ghidra_program_model_address import AddressFactory, Address

class TestCodeBrowserNavigation8051(unittest.TestCase):
    def setUp(self):
        self.env = None
        self.tool = None
        self.addr_factory = None
        self.program = None
        self.cb = None

    def test_operand_navigation(self):
        program_name = "test"
        load_program(program_name)
        show_tool()
        wait_for_posted_swing_runnables()
        cb.go_to(OperandFieldLocation(program, addr("CODE:07ea"), None, None, None, 0, 0))
        self.assertEqual(addr("CODE:07ea"), cb.get_current_address())

        click(cb, 2)
        self.assertEqual(addr("INTMEM:55"), cb.get_current_address())

        cb.go_to(OperandFieldLocation(program, addr("CODE:03f8"), None, None, None, 1, 0))
        self.assertEqual(addr("CODE:03f8"), cb.get_current_address())

        click(cb, 2)
        self.assertEqual(addr("CODE:03fe"), cb.get_current_address())

        cb.go_to(XRefFieldLocation(program, addr("INTMEM:55"), None, addr("CODE:0595"), 1, 2))
        self.assertEqual(addr("INTMEM:55"), cb.get_current_address())

        click(cb, 2)
        self.assertEqual(addr("CODE:07ea"), cb.get_current_address())

    def load_program(self, program_name):
        if not self.program:
            builder = ProgramBuilder("Test", "8051")
            builder.create_memory("CODE", "CODE:0000", 0x1948)
            builder.create_memory("INTMEM", "INTMEM:20", 0xe0)
            builder.set_bytes("CODE:07ea", "f5 55", True)
            builder.set_bytes("CODE:03f8", "30 02 03", True)
            builder.set_bytes("CODE:0595", "75 55 1b", True)

            self.program = builder.get_program()

    def show_tool(self):
        if not self.env:
            self.env = TestEnv()
        self.tool = self.env.get_tool()
        self.cb = self.env.get_plugin(CodeBrowserPlugin())

    def wait_for_posted_swing_runnables(self):
        pass

def addr(address):
    return AddressFactory().get_address(address)

if __name__ == "__main__":
    unittest.main()
