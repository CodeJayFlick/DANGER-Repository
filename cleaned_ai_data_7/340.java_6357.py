import unittest
from unittest import rule, before, testmethod
from ghidra.app.plugin.core.debug.gui.console import DebuggerConsolePlugin, DebuggerConsoleProvider
from ghidra.util.msg import Msg
from help.screenshot.ghidra_screen_shot_generator import GhidraScreenShotGenerator

class DebuggerConsolePluginScreenshots(GhidraScreenShotGenerator):
    def setUp(self):
        self.console_plugin = add_plugin(tool=DebuggerConsolePlugin)
        self.console_provider = wait_for_component_provider(DebuggerConsoleProvider)

        self.console_plugin.add_resolution_action(
            ActionBuilder("Import", method_name=self.method_name())
                .tool_bar_icon(DebuggerResources.ICON_IMPORT)
                .popup_menu_icon(DebuggerResources.ICON_IMPORT)
                .popup_menu_path("Map")
                .description("Import")
                .with_context(ScreenShotActionContext())
                .on_action(lambda ctx: Msg.info(self, "Import clicked"))
        )

        self.console_plugin.add_resolution_action(
            ActionBuilder("Map", method_name=self.method_name())
                .tool_bar_icon(DebuggerResources.ICON_MODULES)
                .popup_menu_icon(DebuggerResources.ICON_MODULES)
                .popup_menu_path("Map")
                .description("Map")
                .with_context(ScreenShotActionContext())
                .on_action(lambda ctx: Msg.info(self, "Map clicked"))
        )

    @testmethod
    def test_capture_debugger_console_plugin(self):
        Msg.warn(self, "This is a warning message")
        Msg.error(self, "This is an error message")

        self.console_plugin.log(DebuggerResources.ICON_DEBUGGER,
            "<html>You can take <b>action</b> to resolve this message<html>",
            ScreenShotActionContext()
        )

        AbstractGhidraHeadedDebuggerGUITest.wait_for_pass(
            lambda: self.assertEqual(3, self.console_plugin.get_row_count())
        )

        capture_isolated_provider(self.console_provider, 600, 300)

if __name__ == "__main__":
    unittest.main()
