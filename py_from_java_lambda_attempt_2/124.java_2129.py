Here is a translation of the provided Java code into equivalent Python:

```Python
class DebuggerSectionMapProposalDialog:
    def __init__(self):
        pass

    BUTTON_SIZE = 32

    class SectionMapTableColumns:
        REMOVE = ("Remove", str)
        MODULE_NAME = ("Module", str, lambda e: e.get_module().name())
        SECTION_NAME = ("Section", str, lambda e: e.get_section().name())
        DYNAMIC_BASE = ("Dynamic Base", int, lambda e: e.get_section().start)
        CHOOSE = ("Choose", str, "Choose Block")
        PROGRAM_NAME = ("Program", str, lambda e: e.get_program().name())
        BLOCK_NAME = ("Block", str, lambda e: e.get_block().name())
        STATIC_BASE = ("Static Base", int, lambda e: e.get_block().start)
        SIZE = ("Size", int, lambda e: e.length)

    class SectionMapPropsalTableModel:
        def __init__(self):
            super().__init__("Section Map")
            self.columns = [DebuggerSectionMapProposalDialog.SectionMapTableColumns._member_map_[name] for name in ["MODULE_NAME", "SECTION_NAME"]]

    def create_table_model(self):
        return DebuggerSectionMapProposalDialog.SectionMapPropsalTableModel()

    def populate_components(self, table, filter_panel):
        super().populate_components()
        self.set_preferred_size(600, 300)

        column_model = table.column_model
        remove_col = column_model.get_column(DebuggerSectionMapProposalDialog.SectionMapTableColumns.REMOVE.ordinal())
        CellEditorUtils.install_button(table, filter_panel, remove_col, DebuggerResources.ICON_DELETE, BUTTON_SIZE, lambda e: self.remove_entry(e))

        dyn_base_col = column_model.get_column(DebuggerSectionMapTableColumns.DYNAMIC_BASE.ordinal())
        dyn_base_col.set_cell_renderer(CustomToStringCellRenderer.MONO_OBJECT)

        choose_col = column_model.get_column(DebuggerSectionMapTableColumns.CHOOSE.ordinal())
        CellEditorUtils.install_button(table, filter_panel, choose_col, DebuggerResources.ICON_PROGRAM, BUTTON_SIZE, lambda e: self.choose_and_set_block(e))

        st_base_col = column_model.get_column(DebuggerSectionMapTableColumns.STATIC_BASE.ordinal())
        st_base_col.set_cell_renderer(CustomToStringCellRenderer.MONO_OBJECT)

        size_col = column_model.get_column(DebuggerSectionMapTableColumns.SIZE.ordinal())
        size_col.set_cell_renderer(CustomToStringCellRenderer.MONO ULONG HEX)

    def choose_and_set_block(self, entry):
        choice = self.provider.ask_block(entry.get_section(), entry.get_program(), entry.get_block())
        if choice is None:
            return

        Swing.run_if_swing_or_run_later(lambda: 
            entry.set_block(choice.key, choice.value)
            table_model.notify_updated(entry))

    def remove_entry(self, e):
        pass
```

Please note that this translation does not include the `CellEditorUtils`, `CustomToStringCellRenderer` and `DebuggerResources`. These are Java classes which do not have direct Python equivalents.