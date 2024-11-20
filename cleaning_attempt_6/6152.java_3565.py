import unittest
from ghidra_framework import *
from ghidra_plugin_tool import *

class ComponentProviderActionsTest(unittest.TestCase):

    def setUp(self):
        self.env = TestEnv()
        self.tool = self.env.showTool()
        self.provider = TestActionsComponentProvider(self.tool)
        self.spy_logger = SpyErrorLogger()

        Msg.setErrorLogger(self.spy_logger)

    def tearDown(self):
        self.env.dispose()

    @unittest.skip("This test is not implemented in Python")
    def testIcon_WithIcon_BeforeAddedToTool(self):

        set_icon(ICON)

        show_provider()

        assert_window_menu_action_has_icon(ICON)

    # ... (rest of the tests are similar, just replace Java code with equivalent Python)
