import tkinter as tk
from ghidra_framework import PluginTool, OptionsService

class EditPropertiesAction:
    OPTIONS_TITLE = "Decompiler"

    def __init__(self, owner: str, tool: PluginTool):
        self.tool = tool
        super().__init__("DecompilerProperties", owner)
        help_location = HelpLocation(HelpTopics.DECOMPILER, "DisplayOptions")
        set_help_location(help_location)
        popup_menu_data = MenuData(["Properties"], "ZED")
        set_popup_menu_data(popup_menu_data)

    def is_enabled_for_context(self, context: ActionContext) -> bool:
        return self.tool.get_service(OptionsService) is not None

    def action_performed(self, context: ActionContext):
        service = self.tool.get_service(OptionsService)
        service.show_options_dialog(f"{self.OPTIONS_TITLE}.Display", "Decompiler")

class HelpLocation:
    def __init__(self, topic: str, subtopic: str):
        pass

class MenuData:
    def __init__(self, items: list[str], label: str):
        self.items = items
        self.label = label

class ActionContext:
    pass

# Create an instance of the EditPropertiesAction class
action = EditPropertiesAction("owner", PluginTool())
