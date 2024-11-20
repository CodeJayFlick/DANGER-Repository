import tkinter as tk
from typing import Dict, Any

class ByteViewerHeader:
    def __init__(self, container: Any) -> None:
        self.container = container
        self.components: Dict[Any, Any] = {}
        font = tk.Font(family="Tahoma", size=11)
        self.config(font=font)
        self.resizable(False)

    def add_column(self, name: str, c: Any) -> None:
        col = tk.Frame(self.container, bg='black', width=100)
        col.pack(side=tk.LEFT)
        self.components[c] = col
        self.column_model.insert('', 'end', values=[name])

    def remove_column(self, c: Any) -> None:
        if c in self.components:
            column_index = list(self.components.keys()).index(c)
            self.column_model.delete(column_index)

    def get_preferred_size(self) -> tuple[int, int]:
        return 100, 20

    def set_column_name(self, c: Any, name: str) -> None:
        if c in self.components:
            column_index = list(self.components.keys()).index(c)
            self.column_model.set(column_index, values=[name])

    def add_column_model_listener(self, l: Any) -> None:
        pass

    def remove_column_model_listener(self, l: Any) -> None:
        pass

    def paint(self, g: Any) -> None:
        pass
