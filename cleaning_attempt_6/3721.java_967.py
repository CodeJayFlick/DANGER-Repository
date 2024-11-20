class DataTypeSyncDialog:
    def __init__(self, plugin: 'DataTypeManagerPlugin', client_name: str, source_name: str,
                 data_type_sync_info_list: list, preselected_data_types: set, operation_name: str, title: str):
        self.plugin = plugin
        self.operation_name = operation_name

        self.sync_panel = DataTypeSyncPanel(data_type_sync_info_list, preselected_data_types, self)
        self.compare_panel = DataTypeComparePanel(client_name, source_name)

        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, self.sync_panel, self.compare_panel)
        split_pane.set_resize_weight(0.6)
        main_panel = JPanel(BorderLayout())
        main_panel.add(split_pane, BorderLayout.CENTER)
        add_work_panel(main_panel)
        initialize()
        create_actions()

    def close(self):
        super().close()
        self.sync_panel.dispose()

    def initialize(self):
        add_ok_button()
        set_ok_button_text(self.operation_name)
        add_cancel_button()
        set_help_location(HelpLocation(self.plugin.get_name(), "Commit_Changes_To_Archive"))

    def create_actions(self):
        select_all_action = DockingAction("Select All", "Sync Dialog", False)
        select_all_action.action_performed = lambda context: self.sync_panel.select_all()

        deselect_all_action = DockingAction("Deselect All", "Sync Dialog", False)
        deselect_all_action.action_performed = lambda context: self.sync_panel.deselect_all()

    def data_type_selected(self, sync_info):
        if sync_info is not None:
            self.compare_panel.set_data_types(sync_info.get_ref_data_type(), sync_info.get_source_data_type())
        else:
            self.compare_panel.set_data_types(None, None)

    def ok_callback(self):
        selected_infos = self.sync_panel.get_selected_infos()
        close()

    def cancel_callback(self):
        cancelled = True
        close()

    @property
    def selected_infos(self) -> list:
        return self._selected_infos

    def set_selected_infos(self, value: list):
        self._selected_infos = value


class DataTypeSyncPanel:
    def __init__(self, data_type_sync_info_list: list, preselected_data_types: set, parent):
        self.parent = parent
        self.data_type_sync_info_list = data_type_sync_info_list
        self.preselected_data_types = preselected_data_types

    def select_all(self):
        # implement the logic for selecting all here

    def deselect_all(self):
        # implement the logic for deselecting all here


class DataTypeComparePanel:
    def __init__(self, client_name: str, source_name: str):
        self.client_name = client_name
        self.source_name = source_name

    def set_data_types(self, ref_data_type, source_data_type):
        # implement the logic for setting data types here


class HelpLocation:
    def __init__(self, plugin_name: str, help_text: str):
        self.plugin_name = plugin_name
        self.help_text = help_text

    @property
    def get_name(self) -> str:
        return self.plugin_name

    @property
    def get_help_text(self) -> str:
        return self.help_text


class DataTypeManagerPlugin:
    # implement the logic for this class here


# Usage example:

plugin = DataTypeManagerPlugin()
dialog = DataTypeSyncDialog(plugin, "Client Name", "Source Name",
                             [DataTypeSyncInfo(),], set([DataTypeSyncInfo()]), "Operation Name", "Title")
