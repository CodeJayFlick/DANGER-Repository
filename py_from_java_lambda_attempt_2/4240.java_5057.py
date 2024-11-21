Here is the translation of the Java code into Python:

```Python
import os
from tkinter import *
from tkinter.filedialog import askopenfilename, asksaveasfilename
from tkinter.messagebox import showinfo

class SaveDialog:
    def __init__(self, parent, title):
        self.parent = parent
        self.title = title
        self.component_provider = None
        self.script_file = None
        self.provider = None
        self.paths = []
        self.list_panel = None
        self.name_field = None
        self.cancelled = False

    def show(self, component_provider, script_file):
        self.component_provider = component_provider
        self.script_file = script_file
        self.provider = GhidraScriptUtil.get_provider(script_file)
        self.paths = list(component_provider.get_writable_script_directories())

        path_panel = self.build_path_panel()
        name_panel = self.build_name_panel()

        panel = Panel(orient=TOP, borderwidth=10)
        if len(self(paths)) > 0:
            panel.add(path_panel, TOP)
            panel.add(name_panel, BOTTOM)
        else:
            panel.add(name_panel, TOP)

        self.parent.add(panel, TOP)
        self.add_ok_button()
        self.add_cancel_button()
        self.set_default_button()

    def build_name_panel(self):
        name_field = Entry(width=20)
        if self.script_file is not None:
            name_field.insert(0, self.script_file.name)
        else:
            name_field.insert(0, "")

        panel = Panel(orient=TOP, borderwidth=10)
        label = Label(text="Enter script file name:")
        panel.add(label, TOP)
        panel.add(name_field, TOP)

        return panel

    def build_path_panel(self):
        list_model = ListModel()
        for path in self.paths:
            list_model.append(path)

        list_panel = ListPanel(list_model=list_model)
        if self.script_file is not None:
            list_panel.set_selected_value(self.script_file.parent)

        mll = MultiLineLabel(text="Please select a directory:")
        panel = Panel(orient=TOP, borderwidth=10)
        panel.add(mll, TOP)
        panel.add(list_panel, TOP)

        return panel

    def dialog_shown(self):
        text = self.name_field.get()
        end_index = len(text) - 1
        dot_index = text.rfind('.')
        if dot_index != -1:
            end_index = dot_index + 1

        self.name_field.focus_set()
        self.name_field.select(0, end_index)
        super().dialog_shown()

    def ok_callback(self):
        if len(self.paths) > 0 and list_panel.get_selected_index() == -1:
            showinfo("Error", "Please select a directory.")
            return

        if len(name_field.get()) == 0:
            showinfo("Error", "Please enter a file name.")
            return

        if len(name_field.get()) > 100:
            showinfo("Error", "File name is too long.")
            return

        error_message = self.get_duplicate_name_error_message(self.name_field.get())
        if error_message is not None:
            showinfo("Error", error_message)
            return

        self.close()

    def get_duplicate_name_error_message(self, name):
        existing_info = self.component_provider.info_manager.get_existing_script_info(name)
        if existing_info is not None:
            source_file = existing_info.source_file
            if os.path.exists(source_file):
                # we have a script info and a file on disk--do not overwrite
                return "Duplicate script name."
            else:
                return None  # allow overwrite of script, as it has been deleted on disk

        directory = self.get_directory()
        user_choice = os.path.join(directory, name)
        if os.path.exists(user_choice):
            return "File already exists on disk."

        return None

    def cancel_callback(self):
        self.cancelled = True
        super().cancel_callback()

    def is_cancelled(self):
        return self.cancelled

    def value_changed(self, e):
        if not name_field.get().startswith(GhidraScriptConstants.DEFAULT_SCRIPT_NAME):
            return

        try:
            script_file = GhidraScriptUtil.create_new_script(self.provider, self.get_directory(), self.component_provider.script_directories)
            name_field.insert(0, script_file.name)
        except IOException as ioe:
            script_file = None
            name_field.delete(0, END)

    def get_directory(self):
        if len(self.paths) == 0 and self.script_file is not None:
            return self.script_file.parent

        index = list_panel.get_selected_index()
        if index < 0:
            return None

        return self(paths)[index]

    def file(self):
        directory = self.get_directory()
        if directory is None or len(name_field.get()) == 0:
            return None

        name = name_field.get()
        if not name.lower().endswith(self.provider.extension):
            name += self.provider.extension
        return os.path.join(directory, name)
```

Note: This translation assumes that the `GhidraScriptUtil` class and its methods are available in Python.