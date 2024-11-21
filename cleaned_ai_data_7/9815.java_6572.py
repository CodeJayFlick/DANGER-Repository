import tkinter as tk
from typing import Any

class GTableAutoLookup:
    def __init__(self, table: Any):
        self.table = table

    def get_current_row(self) -> int:
        return self.table.selection_get()[0]

    def get_row_count(self) -> int:
        return len(self.table.get_children())

    def get_value_string(self, row: int, col: int) -> str | None:
        renderer = self.table.cellrenderer(row, col)
        if isinstance(renderer, tk.Label):
            self.table.tag_configure("selected", background="blue")
            return renderer.cget("text")

        value = self.table.set(row, col)[0]
        return str(value) if value is not None else None

    def is_sortable_table_model(self) -> bool:
        return isinstance(self.table.model(), SortedTableModel)

    def is_sorted(self, column: int) -> bool:
        if not self.is_sortable_table_model():
            return False
        sorted_model = self.table.model()
        return column == sorted_model.get_primary_sort_column_index()

    def is_sorted_ascending(self) -> bool:
        if not self.is_sortable_table_model():
            return False
        sorted_model = self.table.model()
        primary_sort_column_index = sorted_model.get_primary_sort_column_index()
        sort_state = sorted_model.get_table_sort_state().get_column_sort_state(primary_sort_column_index)
        return sort_state.is_ascending()

    def match_found(self, row: int) -> None:
        self.table.selection_set(row, row)
        rect = self.table.cell_rectangle(row, 0, False)
        self.table.see(rect)

class SortedTableModel:
    pass

class TableSortState:
    pass
