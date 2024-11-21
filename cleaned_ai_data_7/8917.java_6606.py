class SetVTMatchFromOneToManyAction:
    MENU_GROUP = "VT_MAIN_MENU_GROUP"
    SET_MATCH_ICON = None  # Load icon from resources or file path

    def __init__(self, controller, add_to_toolbar):
        self.controller = controller
        super().__init__("Select Same Match In Version Tracking Matches Table", VTPlugin.OWNER)
        
        if add_to_toolbar:
            set_tool_bar_data(SET_MATCH_ICON, MENU_GROUP)

        menu_data = {"menu_items": ["Select Match in VT Matches Table"], "icon": SET_MATCH_ICON, "group": MENU_GROUP}
        self.set_popup_menu_data(menu_data)
        self.enabled = False
        help_location = HelpLocation("VersionTrackingPlugin", "Select_Same_Match_In_Version_Tracking_Matches_Table")
        self.set_help_location(help_location)

    def actionPerformed(self, context):
        if isinstance(context, VTMatchOneToManyContext):
            match = self.get_selected_match(context)
            if match is not None:
                self.controller.set_selected_match(match)

    def get_selected_match(self, context):
        selected_matches = context.selected_matches
        if len(selected_matches) == 1:
            return selected_matches[0]
        return None

    def is_enabled_for_context(self, context):
        if isinstance(context, VTMatchOneToManyContext):
            match = self.get_selected_match(context)
            return match is not None
        return False

    def is_add_to_popup(self, context):
        if isinstance(context, VTMatchOneToManyContext):
            return True
        return False


class HelpLocation:
    def __init__(self, plugin_name, help_topic):
        self.plugin_name = plugin_name
        self.help_topic = help_topic


class ToolBarData:
    def __init__(self, icon, group):
        self.icon = icon
        self.group = group

class MenuData:
    def __init__(self, menu_items, icon, group):
        self.menu_items = menu_items
        self.icon = icon
        self.group = group


# Usage example:

controller = VTController()
action = SetVTMatchFromOneToManyAction(controller, True)
