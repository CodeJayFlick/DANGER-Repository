class BatchImportTableModel:
    class COLS:
        SELECTED = ("Selected", True)
        FILETYPE = ("File Type", False)
        LOADER = ("Loader", False)
        LANG = ("Language", True)
        FILES = ("Files", False)

        def __init__(self, column_label, editable):
            self.column_label = column_label
            self.editable = editable

    def __init__(self, batch_info: 'BatchInfo'):
        self.batch_info = batch_info
        self.list = batch_info.get_groups()

    @property
    def name(self) -> str:
        return "Batch Import"

    def refresh_data(self):
        self.list = self.batch_info.get_groups()
        self.fire_table_data_changed()

    def create_sort_comparator(self, column_index: int) -> 'Comparator[BatchGroup]':
        comp = super().create_sort_comparator(column_index)
        if COLS.SELECTED == self.COLS.get_col(column_index):
            return comp.reversed().thenComparing(lambda bg1, bg2: -bg1.size() + bg2.size())
        return comp

    def get_column_count(self) -> int:
        return len(COLS.__dict__.values())

    def get_column_name(self, column_index: int) -> str:
        return COLS.get_col(column_index).column_label

    def get_column_class(self, column_index: int) -> type:
        col = self.COLS.get_col(column_index)
        if col == BatchImportTableModel.COLS.SELECTED:
            return bool
        elif col == BatchImportTableModel.COLS.FILETYPE or col == BatchImportTableModel.COLS.LOADER:
            return str
        elif col == BatchImportTableModel.COLS LANG:
            from . import BatchGroupLoadSpec
            return type(BatchGroupLoadSpec)
        elif col == BatchImportTableModel.COLS.FILES:
            from . import BatchGroup
            return type(BatchGroup)
        else:
            return object

    def is_sortable(self, column_index: int) -> bool:
        return True

    def is_cell_editable(self, row_index: int, column_index: int) -> bool:
        col = self.COLS.get_col(column_index)
        if col == BatchImportTableModel.COLS.SELECTED or col == BatchImportTableView.COLS.LANG:
            return False
        else:
            return True

    def get_model_data(self):
        return self.list

    def set_value_at(self, value: object, row_index: int, column_index: int) -> None:
        if row_index >= len(self.list):
            return
        row = self.list[row_index]
        col = self.COLS.get_col(column_index)
        if col == BatchImportTableModel.COLS.SELECTED:
            new_value = bool(value)
            if new_value and not row.selected_batch_group_load_spec:
                from . import Msg
                Msg.show_warn(self, None, "Missing language", "Select a language for this group before enabling")
                return
            row.enabled = new_value
        elif col == BatchImportTableModel.COLS.LANG:
            row.selected_batch_group_load_spec = value
        # ignore FILES column

    def get_column_value_for_row(self, row: 'BatchGroup', column_index: int) -> object:
        col = self.COLS.get_col(column_index)
        if col == BatchImportTableModel.COLS.SELECTED:
            return bool(row.enabled)
        elif col == BatchImportTableModel.COLS.FILETYPE:
            from . import StringUtils
            return StringUtils.default_string(row.criterion.file_ext, "<no ext>")
        elif col == BatchImportTableModel.COLS.LOADER:
            return row.criterion.loader
        elif col == BatchImportTableModel.COLS LANG:
            return row.selected_batch_group_load_spec
        elif col == BatchImportTableModel.COLS.FILES:
            return row
        else:
            return "unknown column"
