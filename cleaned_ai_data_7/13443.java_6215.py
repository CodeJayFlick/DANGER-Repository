import unittest
from ghidra import *
from ghidra_framework_plugintool_util import PluginException
from ghidra_bitpatterns_gui import *

class FunctionBitPatternsExplorerPluginScreenShots(unittest.TestCase):

    def test_data_gathering_params(self):
        tool = GhidraTool()
        plugin = FunctionBitPatternsExplorerPlugin(tool)
        try:
            tool.add_plugin(plugin)
        except PluginException as e:
            print(f"Error: {e}")

        perform_action(FunctionBitPatternsMainProvider.EXPLORE_FUNCTION_PATTERNS_TEXT, "TestCodeBrowser", False)

        capture_dialog()

    def test_tabbed_view(self):
        tool = GhidraTool()
        plugin = FunctionBitPatternsExplorerPlugin(tool)
        try:
            tool.add_plugin(plugin)
        except PluginException as e:
            print(f"Error: {e}")

        perform_action(FunctionBitPatternsMainProvider.EXPLORE_FUNCTION_PATTERNS_TEXT, "TestCodeBrowser", False)

        press_ok_on_dialog()

    def run_swing(self):
        pass

if __name__ == "__main__":
    unittest.main()
