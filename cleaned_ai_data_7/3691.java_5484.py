class RevertDataTypeAction:
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__("Revert Data Type", plugin.name)
        self.set_popup_menu_data(["Revert"], "Sync")
        self.enabled = True

    def is_enabled_for_context(self, context):
        if not isinstance(context, DataTypesActionContext):
            return False
        
        g_tree = context.get_context_object()
        selection_paths = g_tree.get_selection_paths()
        
        if selection_paths is None or len(selection_paths) != 1:
            return False
        
        node = selection_paths[0].get_last_component()
        if not isinstance(node, DataTypeNode):
            return False

        data_type_node = node
        data_type = data_type_node.data_type
        handler = self.plugin.get_data_type_manager_handler()
        sync_status = get_sync_status(handler, data_type)

        match sync_status:
            case UNKNOWN:
                return False
            case COMMIT:
                return True
            case CONFLICT | IN_SYNC | ORPHAN | UPDATE:
                return False

    def action_performed(self, context):
        g_tree = context.get_context_object()

        selection_paths = g_tree.get_selection_paths()
        
        if selection_paths is None or len(selection_paths) != 1:
            return
        
        node = selection_paths[0].get_last_component()
        if isinstance(node, DataTypeNode):
            data_type_node = node
            data_type = data_type_node.data_type
            dtm = data_type.get_data_type_manager()
            handler = self.plugin.get_data_type_manager_handler()
            source_archive = data_type.source_archive
            
            if not dtm.is_updatable():
                show_unmodifiable_archive_error_message(g_tree, "Revert Failed", dtm)
                return

            source_dtm = handler.get_data_type_manager(source_archive)

            if source_dtm is None:
                Msg.show_info(self.__class__, g_tree, "Revert Failed",
                              f"Source Archive not open: {source_archive.name}")
                return
            
            self.plugin.revert(data_type)

            synchronizer = DataTypeSynchronizer(handler, dtm, source_archive)
            synchronizer.resync_out_of_sync_in_time_only_data_types()

def get_sync_status(handler, data_type):
    # This function is missing in the original Java code
    pass

def show_unmodifiable_archive_error_message(g_tree, title, message):
    # This function is missing in the original Java code
    pass
