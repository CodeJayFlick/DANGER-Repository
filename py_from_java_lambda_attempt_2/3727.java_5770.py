Here is the translation of the given Java code into equivalent Python:

```Python
class DataTypeSyncTableModel:
    CHECKED_COL = 0
    STATUS_OL = 1
    NAME_COL = 2
    REF_PATH_COL = 3
    CHANGE_TIME_COL = 4

    def __init__(self, list_data_types_to_display, preselected_infos, show_source_change_time):
        self.show_source_change_time = show_source_change_time
        self.row_data_list = []
        for data_type_sync_info in list_data_types_to_display:
            self.row_data_list.append(RowData(data_type_sync_info, preselected_infos.get(data_type_sync_info)))

    def get_name(self):
        return "Datatype Sync"

    @property
    def column_names(self):
        return ["Apply", "Status", "Datatype", "Category Path", "Change Time"]

    def get_row_count(self):
        return len(self.row_data_list)

    def get_column_count(self):
        return len(self.column_names)

    def get_column_value_for_row(self, row_data, column_index):
        if isinstance(row_data.sync_info.get_sync_state(), str):
            sync_state = row_data.sync_info.get_sync_state()
        else:
            sync_state = "Unknown"
        
        if column_index == self.CHECKED_COL:
            return row_data.selected
        elif column_index == self.STATUS_OL:
            return sync_state
        elif column_index == self.NAME_COL:
            return row_data.sync_info.name
        elif column_index == self.REF_PATH_COL:
            return row_data.sync_info.get_ref_dt_path()
        elif column_index == self.CHANGE_TIME_COL:
            if show_source_change_time:
                return row_data.sync_info.last_change_time.strftime("%Y-%m-%d %H:%M:%S")
            else:
                return None
        return None

    def get_model_data(self):
        return self.row_data_list

    def set_value_at(self, value, row_index, column_index):
        if column_index == self.CHECKED_COL:
            self.row_data_list[row_index].selected = bool(value)
        self.fire_table_rows_updated(row_index, row_index)

    @property
    def column_class(self):
        if isinstance(self.column_names[self.CHECKED_COL], str):
            return str
        elif isinstance(self.column_names[self.STATUS_OL], str):
            return str
        else:
            return bool

    def get_column_name(self, column_index):
        return self.column_names[column_index]

    def is_cell_editable(self, row_index, column_index):
        if column_index == self.CHECKED_COL:
            return True
        return False

    def is_sortable(self, column_index):
        return True

    def get_sync_info(self, selected_index):
        return self.row_data_list[selected_index].sync_info

    def select_all(self):
        for row_data in self.row_data_list:
            row_data.selected = True
        self.fire_table_data_changed()

    def deselect_all(self):
        for row_data in self.row_data_list:
            row_data.selected = False
        self.fire_table_data_changed()

    def has_unresolved_data_types(self):
        return any(not row_data.selected for row_data in self.row_data_list)

    def get_selected_items(self):
        selected_items = []
        for row_data in self.row_data_list:
            if row_data.selected:
                selected_items.append(row_data.sync_info)
        return selected_items

class RowData:
    def __init__(self, sync_info, select):
        self.sync_info = sync_info
        self.selected = select

    @property
    def selected(self):
        return self._selected

    @selected.setter
    def selected(self, value):
        self._selected = bool(value)

class RowDataSorter:
    def __init__(self, sort_column):
        self.sort_column = sort_column

    def compare(self, row_data1, row_data2):
        if isinstance(row_data1.sync_info.get_sync_state(), str) and isinstance(row_data2.sync_info.get_sync_state(), str):
            return 0
        elif not row_data1.selected and not row_data2.selected:
            return 0
        elif row_data1.selected and not row_data2.selected:
            return -1
        elif not row_data1.selected and row_data2.selected:
            return 1

        if self.sort_column == DataTypeSyncTableModel.CHECKED_COL:
            return compare_state(row_data1.selected, row_data2.selected)
        elif self.sort_column == DataTypeSyncTableModel.STATUS_OL:
            return SystemUtilities.compare_to(row_data1.sync_info.get_sync_state(), row_data2.sync_info.get_sync_state())
        elif self.sort_column == DataTypeSyncTableModel.NAME_COL:
            return row_data1.sync_info.name.casefold().compare(row_data2.sync_info.name.casefold())
        elif self.sort_column == DataTypeSyncTableModel.REF_PATH_COL:
            return row_data1.sync_info.get_ref_dt_path().casefold().compare(row_data2.sync_info.get_ref_dt_path().casefold())
        elif self.sort_column == DataTypeSyncTableModel.CHANGE_TIME_COL:
            if show_source_change_time:
                date1 = datetime.strptime(row_data1.sync_info.last_change_time, "%Y-%m-%d %H:%M:%S")
                date2 = datetime.strptime(row_data2.sync_info.last_change_time, "%Y-%m-%d %H:%M:%S")
                return compare_dates(date1.timestamp(), date2.timestamp())
            else:
                return 0

    def compare_state(self, can1, can2):
        if can1 == can2:
            return 0
        elif can1 and not can2:
            return -1
        elif not can1 and can2:
            return 1
        return 0

    def compare_dates(self, date1, date2):
        if date1 < date2:
            return -1
        elif date1 > date2:
            return 1
        return 0