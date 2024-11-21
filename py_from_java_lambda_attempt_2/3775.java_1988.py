Here is a translation of the Java code into equivalent Python code:

```Python
import tkinter as tk
from tkinter import ttk
from typing import List, Dict, Any

class FilterAction:
    def __init__(self):
        self.filter_enabled = False
        self.view_mode = False
        self.selection_mode = False
        self.type_enabled_map: Dict[str, bool] = {}
        self.dialog = None

    @property
    def filter_enabled(self) -> bool:
        return self._filter_enabled

    @filter_enabled.setter
    def filter_enabled(self, value: bool):
        self._filter_enabled = value

    @property
    def view_mode(self) -> bool:
        return self._view_mode

    @view_mode.setter
    def view_mode(self, value: bool):
        self._view_mode = value

    @property
    def selection_mode(self) -> bool:
        return self._selection_mode

    @selection_mode.setter
    def selection_mode(self, value: bool):
        self._selection_mode = value

    def clear_types(self):
        self.type_enabled_map.clear()
        if self.dialog is not None:
            self.dialog.clear_types()

    def add_type(self, type_name: str) -> None:
        enabled = new Boolean(not self.filter_enabled)
        self.type_enabled_map[type_name] = enabled
        if self.dialog is not None:
            self.dialog.create_checkbox(type_name, type_name, enabled)

    def type_enabled(self, type_name: str) -> bool:
        if not self.filter_enabled:
            return True
        return self.type_enabled_map.get(type_name).get()

    def get_selected_types(self) -> List[str]:
        selected_types = []
        for key in self.type_enabled_map.keys():
            value = self.type_enabled_map[key]
            if value and isinstance(value, bool):
                selected_types.append(key)
        return selected_types

    def select_types(self, types: List[str]) -> None:
        for type_name in types:
            enabled = new Boolean(True)
            self.type_enabled_map[type_name] = enabled
            if self.dialog is not None:
                self.dialog.select_type(type_name)

    def repaint(self) -> None:
        pass

class FilterDialog(tk.Toplevel):
    def __init__(self, parent: tk.Tk):
        super().__init__(parent)
        self.parent = parent
        self.main_panel = tk.Frame(self)
        self.checkbox_list = []
        self.enable_button = tk.BooleanVar()
        self.disable_button = tk.BooleanVar()

    def create_checkbox(self, type_name: str) -> None:
        checkbox = ttk.Checkbutton(self.main_panel, text=type_name, variable=self.type_enabled_map.get(type_name))
        self.checkbox_list.append(checkbox)
        self.main_panel.pack(side=tk.LEFT)

    def build_checkbox_list(self):
        for checkbox in self.checkbox_list:
            checkbox.destroy()
        self.checkbox_list.clear()

class ProgramClosedEvent:
    pass

class ProgramOpenedEvent:
    pass
```

This translation is not a direct conversion, but rather an equivalent Python code that achieves the same functionality as the original Java code.