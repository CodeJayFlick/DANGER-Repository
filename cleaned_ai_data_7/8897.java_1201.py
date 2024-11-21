class DontKnowMarkupItemAction:
    MENU_GROUP = "EDIT_MENU_GROUP"

    def __init__(self, controller, add_to_toolbar):
        super().__init__(controller, "Don't Know")
        if add_to_toolbar:
            self.set_tool_bar_data({"icon": DONT_KNOW_ICON, "menu_group": MENU_GROUP})
        menu_data = {"name": ["Don't Know"], "icon": DONT_KNOW_ICON, "menu_group": MENU_GROUP}
        self.set_popup_menu_data(menu_data)
        self.enabled = False
        self.help_location = HelpLocation("VersionTrackingPlugin", "Tag_Markup_Item_Dont_Know")

    def get_tag_type(self):
        return VTMarkupItemConsideredStatus.IGNORE_DONT_KNOW

DONT_KNOW_ICON = ...  # assume this is defined elsewhere in the codebase
VTMarkupItemConsideredStatus = ...  # assume this is defined elsewhere in the codebase
HelpLocation = ...  # assume this is defined elsewhere in the codebase
