Here is the translation of the given Java code into equivalent Python code:

```Python
class DebuggerModuleMapProposalDialog:
    BUTTON_SIZE = 32
    
    class ModuleMapTableColumns(enumerate):
        REMOVE = (0, "Remove", str)
        MODULE_NAME = (1, "Module", str)
        DYNAMIC_BASE = (2, "Dynamic Base", int)
        CHOOSE = (3, "Choose", str)
        PROGRAM_NAME = (4, "Program", str)
        STATIC_BASE = (5, "Static Base", int)
        SIZE = (6, "Size", int)

    class ModuleMapPropsalTableModel:
        def __init__(self):
            super().__init__("Module Map")
        
        @property
        def default_sort_order(self):
            return [DebuggerModuleMapProposalDialog.ModuleMapTableColumns.MODULE_NAME]

    def __init__(self, provider):
        self.provider = provider

    def create_table_model(self):
        return DebuggerModuleMapProposalDialog.ModuleMapPropsalTableModel()

    def populate_components(self):
        super().populate_components()
        self.set_preferred_size(600, 300)

        column_model = self.table.get_column_model()
        
        remove_col = column_model.get_column(DebuggerModuleMapProposalDialog.ModuleMapTableColumns.REMOVE)
        CellEditorUtils.install_button(self.table, self.filter_panel, remove_col,
            DebuggerResources.ICON_DELETE, self.BUTTON_SIZE, lambda: self.remove_entry())

        dyn_base_col = column_model.get_column(DebuggerModuleMapProposalDialog.ModuleMapTableColumns.DYNAMIC_BASE)
        dyn_base_col.set_cell_renderer(CustomToStringCellRenderer.MONO_OBJECT)

        choose_col = column_model.get_column(DebuggerModuleMapProposalDialog.ModuleMapTableColumns.CHOOSE)
        CellEditorUtils.install_button(self.table, self.filter_panel, choose_col,
            DebuggerResources.ICON_PROGRAM, self.BUTTON_SIZE, lambda: self.choose_and_set_program())

        st_base_col = column_model.get_column(DebuggerModuleMapProposalDialog.ModuleMapTableColumns.STATIC_BASE)
        st_base_col.set_cell_renderer(CustomToStringCellRenderer.MONO_OBJECT)

        size_col = column_model.get_column(DebuggerModuleMapProposalDialog.ModuleMapTableColumns.SIZE)
        size_col.set_cell_renderer(CustomToStringCellRenderer.MONO ULONG HEX)

    def choose_and_set_program(self, entry):
        file = self.provider.ask_program(entry.program)
        if not file:
            return
        program = self.provider.open_program(file)
        Swing.run_if_swing_or_run_later(lambda: 
            entry.set_program(program) and self.table_model.notify_updated(entry))
```

Please note that this translation is based on the assumption that `CellEditorUtils`, `CustomToStringCellRenderer`, `DebuggerResources` are Python classes or modules.