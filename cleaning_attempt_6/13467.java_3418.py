import unittest

class ProgramTreePluginScreenShots(unittest.TestCase):
    def __init__(self):
        super().__init__()

    @unittest.skip
    def test_view_manager(self):
        remove_flow_arrows()
        close_provider(DataTypesProvider)
        set_divider_percentage(0.25, DataTypesProvider, CodeViewerProvider)
        capture_window(tool.get_tool_frame(), 1000, 600)

if __name__ == '__main__':
    unittest.main()
