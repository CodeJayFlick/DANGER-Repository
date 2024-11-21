Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import filedialog, messagebox
from typing import List

class ExternalReferencesProvider:
    def __init__(self):
        self.main_panel = None
        self.table_model = None
        self.program = None
        self.row_to_highlight_during_next_reload = None
        self.domain_object_listener = None

    def set_program(self, program: object) -> None:
        if self.program is not None:
            self.program.remove_listener(self.domain_object_listener)
        self.program = program
        if self.program is not None:
            self.program.add_listener(self.domain_object_listener)

    @property
    def main_panel(self):
        return self._main_panel

    @main_panel.setter
    def main_panel(self, value: object) -> None:
        self._main_panel = value

    @property
    def table_model(self):
        return self._table_model

    @table_model.setter
    def table_model(self, value: object) -> None:
        self._table_model = value

    @property
    def program(self):
        return self._program

    @program.setter
    def program(self, value: object) -> None:
        if self.program is not None:
            self.program.remove_listener(self.domain_object_listener)
        self._program = value
        if self.program is not None:
            self.program.add_listener(self.domain_object_listener)

    def create_actions(self):
        action_builder = tk.simpledialog.asksimpletext("Add External Program Name", "Enter Name")
        action_builder.popup_menu_path("Add External Program")
        action_builder.popup_menu_icon(ADD_ICON)
        action_builder.tool_bar_icon(ADD_ICON)
        action_builder.enabled_when(lambda: self.program is not None)
        action_builder.on_action(self.add_external_program)

    def add_external_program(self):
        dialog = tk.simpledialog.asksimpletext("New External Program", "Enter Name")
        if dialog.is_cancelled():
            return
        new_name = dialog.get_value().strip()
        if new_name == "":
            messagebox.showerror(self, "Invalid Input", "External program name cannot be empty")
            return
        cmd = AddExternalNameCmd(new_name)
        self.program.execute(cmd)

    def delete_external_program(self):
        external_manager = self.program.get_external_manager()
        compound_cmd = CompoundCmd("Delete External Program Name")
        for name in get_selected_names():
            if has_locations(name, external_manager):
                messagebox.showerror(self, "Delete Failure", f"The following external reference names could not be deleted because they contain external locations:\n{buf}")
            else:
                cmd.add(RemoveExternalNameCmd(name))
        self.program.execute(cmd)

    def set_external_program_association(self):
        selected_names = get_selected_names()
        if len(selected_names) != 1:
            messagebox.showerror(self, "Invalid Input", "Must be exactly one for us to be enabled.")
            return
        name = selected_names[0]
        dialog = tk.simpledialog.askdirectory("Choose External Program (" + name + ")")
        if not dialog.is_cancelled():
            domain_file = dialog.get_domain_file()
            path_name = domain_file.toString()
            cmd = SetExternalNameCmd(name, path_name)
            self.program.execute(cmd)

    def clear_external_association(self):
        compound_cmd = CompoundCmd("Clear External Program Associations")
        for name in get_selected_names():
            cmd.add(ClearExternalNameCmd(name))
        self.program.execute(cmd)

class AddExternalNameCmd:
    pass

class RemoveExternalNameCmd:
    pass

class SetExternalNameCmd:
    pass

class ClearExternalNameCmd:
    pass

def has_locations(name: str, external_manager):
    return True  # todo implement this method

def get_selected_names():
    return []  # todo implement this method
```

Please note that the above Python code is not a direct translation of Java to Python. It's more like an interpretation based on my understanding of your requirements.