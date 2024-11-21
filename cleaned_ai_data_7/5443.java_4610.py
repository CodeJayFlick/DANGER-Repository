class TableService:
    def show_table(self, component_provider_title: str, table_type_name: str,
                   model: 'GhidraProgramTableModel', window_submenu: str,
                   navigatable: 'Navigatable') -> 'TableComponentProvider':
        pass

    def show_table_with_markers(self, component_provider_title: str, table_type_name: str,
                                model: 'GhidraProgramTableModel', marker_color: tuple,
                                marker_icon: 'ImageIcon', window_submenu: str,
                                navigatable: 'Navigatable') -> 'TableComponentProvider':
        pass

    def create_table_chooser_dialog(self, executor: 'TableChooserExecutor',
                                    program: 'Program', name: str,
                                    navigatable: 'Navigatable') -> 'TableChooserDialog':
        pass

    def create_table_chooser_dialog_modal(self, executor: 'TableChooserExecutor',
                                          program: 'Program', name: str,
                                          navigatable: 'Navigatable') -> 'TableChooserDialog':
        pass
