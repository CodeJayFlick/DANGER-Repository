class RemoveMatchTagAction:
    MENU_GROUP = "VTPlugin.TAG_MENU_GROUP"
    EDIT_TAG_ICON = None  # Replace with your icon loading function
    ACTION_NAME = "Remove VTMatch Tags"

    def __init__(self):
        super().__init__()
        self.setDescription("Remove Match Tag")
        self.setToolBarData({"icon": EDIT_TAG_ICON, "menu_group": MENU_GROUP})
        menu_data = {"options": ["Remove Tag"], "icon": EDIT_TAG_ICON, "menu_group": MENU_GROUP}
        menu_data["set_menu_subgroup"] = 2
        self.setPopupMenuData(menu_data)
        self.setEnabled(False)
        self.help_location = HelpLocation("VersionTrackingPlugin", "Remove_Tag")

    def actionPerformed(self, context):
        self.remove_tag(context)

    def is_enabled_for_context(self, context):
        if not isinstance(context, VTMatchContext):
            return False
        matches = context.get_selected_matches()
        if len(matches) == 0:
            return False
        tag_count = self.calculate_tag_count(matches)
        return tag_count > 0

    def is_add_to_popup(self, context):
        if not isinstance(context, VTMatchContext):
            return False
        match_context = context
        matches = match_context.get_selected_matches()
        if len(matches) == 0:
            return False
        return True

    def calculate_tag_count(self, matches):
        count = 0
        for match in matches:
            tag = match.get_tag()
            if tag is not None and tag != VTMatchTag.UNTAGGED:
                count += 1
        return count

    def remove_tag(self, context):
        match_context = context
        component_provider = match_context.get_component_provider()
        component = component_provider.get_component()

        message = "1 tag?"
        if self.tag_count > 1:
            message = f"{self.tag_count} tags?"

        choice = OptionDialog.show_yes_no_dialog(component, "Remove Match Tag?", f"Remove {message}")
        if choice == OptionDialog.NO_OPTION:
            return

        matches = match_context.get_selected_matches()
        task = ClearMatchTagTask(match_context.get_session(), matches)
        TaskLauncher(task, component)

class HelpLocation:
    def __init__(self, plugin_name, help_topic):
        self.plugin_name = plugin_name
        self.help_topic = help_topic

class OptionDialog:
    NO_OPTION = 0

    @staticmethod
    def show_yes_no_dialog(component, title, message):
        # Replace with your actual dialog implementation
        pass

class TaskLauncher:
    def __init__(self, task, component):
        self.task = task
        self.component = component

# Replace VTMatchContext, VTMatchTag, and ClearMatchTagTask with their Python equivalents or implement them if they don't exist.
