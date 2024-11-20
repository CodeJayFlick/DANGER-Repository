import tkinter as tk
from tkinter import messagebox

class VTMatchApplySettingsAction:
    VERSION_TRACKING_OPTIONS_NAME = "Version Tracking"
    APPLY_MARKUP_OPTIONS = "Apply Markup Options"

    ICON = None  # Load icon using ResourceManager in actual implementation

    MENU_GROUP = "VT_SETTINGS_MENU_GROUP"
    TITLE = "Version Tracking Options"

    def __init__(self, controller):
        self.controller = controller
        super().__init__(TITLE)

        self.setToolBarData(ICON, MENU_GROUP)
        self.setPopupMenuData(["Options...", ICON, MENU_GROUP])
        self.setDescription("Adjust the Apply Mark-up Settings for Applying Matches")
        self.setEnabled(True)
        self.setHelpLocation("VersionTrackingPlugin", "Match_Table_Settings")

    def actionPerformed(self):
        tool = self.controller.get_tool()
        service = tool.getService(OptionsService)
        service.show_options_dialog(f"{self.VERSION_TRACKING_OPTIONS_NAME}.{self.APPLY_MARKUP_OPTIONS}", "Apply")

    def isEnabledForContext(self, context):
        return True

    def isAddToPopup(self, context):
        return True
