import tkinter as tk
from typing import List, Any

class CopyPasteSpecialDialog:
    def __init__(self, plugin: Any, available_types: List[Any], title: str):
        self.available_types = available_types
        self.selected_type = None

        self.main_panel = tk.Frame()
        self.list_panel = tk.Listbox(self.main_panel)
        self.list_panel.pack(side=tk.LEFT)

        for type in available_types:
            self.list_panel.insert(tk.END, type)

        self.main_panel.pack()

    def create_panel(self) -> tk.Frame:
        panel = tk.Frame()
        panel.pack()

        return panel

    def ok_callback(self):
        self.close()
        selected_value = self.list_panel.get(self.list_panel.curselection())
        self.selected_type = selected_value

    def cancel_callback(self):
        self.close()

    def get_selected_type(self) -> Any:
        return self.selected_type
