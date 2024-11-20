class UpdateAction:
    MENU_NAME = "Update Datatypes From"

    def __init__(self, plugin, data_type_manager_handler, dtm, archive_node, source_archive, enabled):
        super().__init__("Update Datatypes From Archive", plugin, data_type_manager_handler, dtm, archive_node, source_archive, enabled)
        self.set_popup_menu_data([MENU_NAME, source_archive.name])
        self.set_help_location(HelpLocation(plugin.name, "Update_Data_Types"))

    def get_menu_order(self):
        return 1

    def get_help_topic(self):
        return "Update_Data_Types"

    def is_appropriate_for_action(self, info):
        if info.get_sync_state() in [UPDATE, CONFLICT]:
            return True
        else:
            return False

    def is_preselected_for_action(self, info):
        return info.get_sync_state() == UPDATE

    def get_operation_name(self):
        return "Update"

    def apply_operation(self, info):
        info.update()

    def get_confirmation_message(self, infos):
        buf = StringBuffer()
        if contains_conflicts(infos):
            buf.append("You are updating one or more conflicts which will OVERWRITE\n")
            buf.append("changes in this program or archive!\n\n")
        buf.append(f"Are you sure you want to UPDATE {len(infos)} datatype(s)?")
        return buf.toString()

    def requires_archive_open_for_editing(self):
        return False

    def get_title(self, source_name, client_name):
        return f"Update Datatype Changes From Archive '{source_name}' To '{client_name}'"


class HelpLocation:
    def __init__(self, plugin_name, help_topic):
        self.plugin_name = plugin_name
        self.help_topic = help_topic

UPDATE = 1
CONFLICT = 2


def contains_conflicts(infos):
    # This function should be implemented based on the given Java code.
    pass
