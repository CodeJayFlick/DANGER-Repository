class CommitAction:
    MENU_NAME = "Commit Datatypes To"

    def __init__(self, plugin, data_type_manager_handler, dtm, archive_node, source_archive, enabled):
        super().__init__("Commit Changes To Archive", plugin, data_type_manager_handler, dtm, archive_node, source_archive, enabled)
        self.set_popup_menu_data([MENU_NAME, source_archive.name])
        self.set_help_location(HelpLocation(plugin.name, "Commit_Data_Types"))

    def get_menu_order(self):
        return 2

    def get_help_topic(self):
        return "Commit_Data_Types"

    def is_appropriate_for_action(self, info):
        if info.get_sync_state() in [DataTypeSyncState.COMMIT, DataTypeSyncState.CONFLICT, DataTypeSyncState.ORPHAN]:
            return True
        else:
            return False

    def is_preselected_for_action(self, info):
        return info.get_sync_state() == DataTypeSyncState.COMMIT

    def get_operation_name(self):
        return "Commit"

    def apply_operation(self, info):
        info.commit()

    def get_confirmation_message(self, infos):
        buf = StringBuffer()
        if self.contains_conflicts(infos):
            buf.append("You are committing one or more conflicts which will OVERWRITE\n")
            buf.append("changes in the source archive!\n\n")
        buf.append(f"Are you sure you want to COMMIT {len(infos)} datatype(s)?")
        return buf.toString()

    def requires_archive_open_for_editing(self):
        return True

    def get_title(self, source_name, client_name):
        return f"Commit Datatype Changes From '{client_name}' To Archive '{source_name}'"

class HelpLocation:
    def __init__(self, plugin_name, topic):
        self.plugin_name = plugin_name
        self.topic = topic

class DataTypeSyncInfo:
    def get_sync_state(self):
        pass  # Implement this method as needed

class DataTypeManagerPlugin:
    def name(self):
        pass  # Implement this method as needed

class ArchiveNode:
    def name(self):
        pass  # Implement this method as needed

class SourceArchive:
    def name(self):
        pass  # Implement this method as needed
