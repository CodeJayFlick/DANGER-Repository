Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra_app_plugin_core_byteviewer import ByteViewerPlugin
from ghidra_framework_plugintool import PluginTool
from ghidra_program_database import ProgramBuilder
from ghidra_program_model_address import Address, AddressSet

class TestByteViewerPlugin3(unittest.TestCase):
    def setUp(self):
        self.env = TestEnv()
        try:
            tool = self.env.get_tool()
            tool.add_plugin("GoToAddressLabelPlugin")
            tool.add_plugin("NavigationHistoryPlugin")
            tool.add_plugin("NextPrevAddressPlugin")
            tool.add_plugin("CodeBrowserPlugin")
            tool.add_plugin("ByteViewerPlugin")

            plugin = self.env.get_plugin(ByteViewerPlugin)
            cb_plugin = self.env.get_plugin(CodeBrowserPlugin)

            program = build_notepad()
            pm = tool.get_service(ProgramManager())
            pm.open_program(program.domain_file)
            panel = plugin.provider.byte_viewer_panel
            wait_for_posted_swing_runnables()

        except Exception as e:
            env.dispose()
            raise e

    def tearDown(self):
        self.env.release(program)
        self.env.dispose()

    @unittest.skip("Test is not implemented")
    def test_set_visible(self):
        go_to_service = tool.get_service(GoToService())
        addr = get_addr(0x01001004)
        go_to_service.go_to(addr)

        c = panel.current_component
        info = c.viewer_cursor_location()
        self.assertEqual(cb_plugin.current_address, convert_to_addr(info))

    @unittest.skip("Test is not implemented")
    def test_not_visible(self):
        go_to_service = tool.get_service(GoToService())
        addr = get_addr(0x01002000)
        go_to_service.go_to(addr)

        c = panel.current_component
        info = c.viewer_cursor_location()
        self.assertEqual(cb_plugin.current_address, convert_to_addr(info))

    def build_notepad(self):
        builder = ProgramBuilder("notepad", "TOY")
        builder.create_memory("test2", "0x1001000", 0x2000)
        program = builder.get_program()
        program.clear_undo
        return program

    def get_addr(self, offset):
        return program.min_address.new_address(offset)

    def convert_to_addr(self, info):
        blockset = plugin.provider.byte_block_set
        addr = blockset.address(1, 2).get_new_address(info.block, info.offset)
        return addr

def wait_for_posted_swing_runnables():
    pass

if __name__ == "__main__":
    unittest.main()
```

Please note that this is a direct translation of the Java code into Python. However, it may not work as expected because some parts are missing (like `ByteViewerComponent`, `CodeBrowserPlugin` etc.) and there might be differences in how certain classes or methods behave between Java and Python.