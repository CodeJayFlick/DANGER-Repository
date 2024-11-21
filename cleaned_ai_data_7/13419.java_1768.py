import unittest
from ghidra import GhidraApp
from ghidra.app.plugin.core.calltree import CallTreeProvider

class TestCallTreePluginScreenShots(unittest.TestCase):

    def test_call_tree_window(self):
        app = GhidraApp()
        provider = app.get_provider(CallTreeProvider)
        split_pane = getattr(provider, 'splitPane')
        if not hasattr(split_pane, 'setResizeWeight'):
            return
        split_pane.set_resize_weight(0.5)

        # capture screenshot here

if __name__ == '__main__':
    unittest.main()
