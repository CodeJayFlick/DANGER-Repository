Here is a translation of the Java code into equivalent Python:

```Python
import tkinter as tk
from typing import List, Set

class DataTypeSyncPanel:
    def __init__(self, list: List[DataTypeSyncInfo], preselected_infos: Set[DataTypeSyncInfo], listener):
        self.listener = listener
        self.create(list, preselected_infos)

    def create(self, list: List[DataTypeSyncInfo], preselected_infos: Set[DataTypeSyncInfo]):
        # Populate the table model.
        self.table_model = DataTypeSyncTableModel(list, preselected_infos, True)
        
        self.sync_table = tk.ttk.Treeview()
        self.sync_table["columns"] = ("name", "checked", "status", "ref_path", "change_time")
        for column in range(5):
            self.sync_table.column(column, width=100)
            self.sync_table.heading(column, text=f"Column {column}")
        
        # Set default column sizes
        for i in range(len(self.table_model.get_headers())):
            column = f"Column {i}"
            if i == 0:
                self.sync_table.column(i, anchor="w", width=60)
            elif i == 1:
                self.sync_table.column(i, anchor="w", width=70)
            else:
                self.sync_table.column(i, anchor="w")
        
        # Populate the table.
        for row in range(len(list)):
            values = [list[row][0], list[row][1], list[row][2], list[row][3], list[row][4]]
            self.sync_table.insert("", "end", values=values)
        
    def dispose(self):
        pass

class DataTypeSyncBooleanRenderer:
    def __init__(self, table_model: tk.ttk.Treeview):
        self.table_model = table_model
    
    def get_cell_renderer_component(self, data):
        c = super().get_cell_renderer_component(data)

        table = data.get_table()
        row = data.get_row_view_index()
        column = data.get_column_view_index()

        model = table.model

        cb.enabled(model.is_cell_editable(row, column))
        return c


class DataTypeSyncTableModel:
    def __init__(self, list: List[DataTypeSyncInfo], preselected_infos: Set[DataTypeSyncInfo], has_unresolved_data_types):
        self.list = list
        self.preselected_infos = preselected_infos
        self.has_unresolved_data_types = has_unresolved_data_types

    def get_headers(self) -> List[str]:
        return ["name", "checked", "status", "ref_path", "change_time"]

    def fire_table_data_changed(self):
        pass


class GhidraTableFilterPanel:
    def __init__(self, table: tk.ttk.Treeview, model):
        self.table = table
        self.model = model

    def dispose(self):
        pass

    def get_model_row(self, row_index) -> int:
        return 0  # Not implemented


class DataTypeSyncListener:
    def data_type_selected(self, info):
        pass


# Usage example:

listener = DataTypeSyncListener()
panel = DataTypeSyncPanel([("Info1", True), ("Info2", False)], {"Info1"}, listener)
```

Please note that this is a translation of the Java code into equivalent Python. The original Java code was complex and had many dependencies, so I have simplified it to make it more understandable in Python.