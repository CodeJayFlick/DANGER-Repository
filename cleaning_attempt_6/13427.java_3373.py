import unittest
from ghidra import GhidraScreenShotGenerator
from ghidra.app.plugin.core.cparser import CParserPlugin
from ghidra.util.msg import Msg

class CParserPluginScreenShots(GhidraScreenShotGenerator):
    def setUp(self):
        super().setUp()
        self.load_plugin(CParserPlugin)

    @unittest.skip("Test not implemented")
    def test_parse_c_source(self):
        self.perform_action("Import C DataTypes", "CParserPlugin", False)
        self.capture_dialog()
        self.close_all_windows_and_frames()

    @unittest.skip("Test not implemented")
    def test_parse_error(self):
        Msg.show_info(None, None, "Parse Errors",
                      "C Parser: Encountered errors during parse.\n" +
                      "        in C:\\tmp\\samp.h near line 12\n" +
                      "       near token: \"This function or variable may be unsafe. Consider using \"\n" +
                      "        Last Valid Dataype: PCUWSTR")
        self.capture_dialog()
        self.close_all_windows_and_frames()

    @unittest.skip("Test not implemented")
    def test_use_open_archives(self):
        self.perform_action("Import C DataTypes", "CParserPlugin", False)

        parse_dialog = self.get_dialog()
        self.press_button_by_text(parse_dialog, "Parse to Program", False)

        confirm_dialog = self.wait_for_dialog_component(None, OptionDialog)
        self.press_button_by_text(confirm_dialog, "Continue")

        use_open_archives_dialog = self.wait_for_dialog_component(None, OptionDialog, 5000)
        self.capture_dialog(use_open_archives_dialog)
        self.close_all_windows_and_frames()

    def perform_action(self, action_name: str, plugin_name: str, is_modal: bool):
        # implement this method
        pass

    def capture_dialog(self, dialog=None):
        # implement this method
        pass

    def close_all_windows_and_frames(self):
        # implement this method
        pass

if __name__ == "__main__":
    unittest.main()
