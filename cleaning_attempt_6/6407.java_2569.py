import unittest
from ghidra.app.plugin.core.programtree import ProgramTreePlugin
from ghidra.framework.plugintool import PluginTool
from ghidra.program.database import ProgramDB
from ghidra.program.model.address import AddressSetView

class TestProgramTree(unittest.TestCase):

    def setUp(self):
        self.env = None
        self.tool = None
        self.program = None
        self.plugin = None
        self.provider = None
        self.program_mgr = None
        self.view_panel = None
        self.tabbedPane = None
        self.cb = None

    @classmethod
    def setUpClass(cls):
        cls.env = TestEnv()
        cls.tool = cls.env.get_tool()
        cls.plugin = ProgramTreePlugin()

    def test_default_tree_view(self):
        provider_service = self.provider.current_view_provider
        assert provider_service is not None
        self.assertEqual(PluginConstants.DEFAULT_TREE_NAME, provider_service.view_name)
        index = self.tabbedPane.selected_index
        self.assertEqual(index, 0)

    # ... other tests

if __name__ == '__main__':
    unittest.main()
