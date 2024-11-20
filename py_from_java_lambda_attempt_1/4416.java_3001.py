Here is the translation of the given Java code into Python:

```Python
import os
from typing import List

class TipOfTheDayPlugin:
    TIP_INDEX = "TIP_INDEX"
    SHOW_TIPS = "SHOW_TIPS"

    def __init__(self, tool):
        self.dialog = None
        self.action = None
        super().__init__()

    def init(self):
        from ghidra.util import HelpLocation

        action = DockingAction("Tips of the day", self.get_name())
        action.set_menu_bar_data(["Help", "Tip of the Day"], ToolConstants.HELP_CONTENTS_MENU_GROUP)
        action.set_enabled(True)
        action.set_help_location(HelpLocation(ToolConstants.TOOL_HELP_TOPIC, "Tip_of_the_day"))
        tool.add_action(action)

        try:
            tips = self.load_tips()
        except Exception as e:
            tips = []

        if len(tips) > 0:
            dialog = TipOfTheDayDialog(self, tips)
        else:
            dialog = None

        self.read_preferences()

    def load_tips(self):
        import io
        from ghidra.util import FileUtilities

        try:
            with open("tips.txt", "r") as f:
                lines = [line.strip() for line in f.readlines()]
                return list(filter(lambda s: len(s) > 0, lines))
        except Exception as e:
            return []

    def dispose(self):
        self.write_preferences()
        if action is not None:
            action.dispose()
        if dialog is not None:
            dialog.close()

    def read_preferences(self):
        import preferences

        tip_index_str = preferences.get_property(TIP_INDEX, "0", True)
        show_tips_str = preferences.get_property(SHOW_TIPS, "true", True)

        try:
            tip_index = int(tip_index_str)
            show_tips = bool(int(show_tips_str))
            if show_tips:
                tip_index = (tip_index + 1) % len(dialog.tips())
                self.write_preferences(tip_index, show_tips)
            dialog.set_tip_index(tip_index)
            dialog.set_show_tips(show_tips)

        except Exception as e:
            pass

    def write_preferences(self):
        if dialog is not None:
            tip_index = dialog.get_tip_index()
            show_tips = dialog.show_tips()

            preferences.set_property(TIP_INDEX, str(tip_index))
            preferences.set_property(SHOW_TIPS, str(show_tips))

            try:
                preferences.store()
            except Exception as e:
                pass

    def write_preferences(self, tip_index: int, show_tips: bool):
        self.read_preferences()

class TipOfTheDayDialog:
    def __init__(self, plugin, tips):
        self.plugin = plugin
        self.tips = tips

    def do_show(self, frame):
        # implementation of the dialog's "doShow" method is missing in this translation
        pass

    def get_number_of_tips(self) -> int:
        return len(self.tips)

    def set_tip_index(self, tip_index: int):
        self.tip_index = tip_index

    def show(self, frame):
        # implementation of the dialog's "show" method is missing in this translation
        pass

    def close(self):
        # implementation of the dialog's "close" method is missing in this translation
        pass

class DockingAction:
    def __init__(self, name: str, plugin_name: str):
        self.name = name
        self.plugin_name = plugin_name

    def set_menu_bar_data(self, menu_items: List[str], group: str):
        # implementation of the "setMenuBarData" method is missing in this translation
        pass

    def dispose(self):
        # implementation of the "dispose" method is missing in this translation
        pass

class ToolConstants:
    HELP_CONTENTS_MENU_GROUP = ""
    TOOL_HELP_TOPIC = ""

class Preferences:
    @staticmethod
    def get_property(key: str, default_value: str, store_if_changed: bool) -> str:
        # implementation of the "get_property" method is missing in this translation
        pass

    @staticmethod
    def set_property(key: str, value: str):
        # implementation of the "set_property" method is missing in this translation
        pass

    @staticmethod
    def store():
        # implementation of the "store" method is missing in this translation
        pass
```

Note that some methods are not implemented as they were left out from the original Java code.