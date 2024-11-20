Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import filedialog, messagebox
from datetime import date

class VersionHistoryPanel:
    def __init__(self, tool, domain_file):
        self.tool = tool
        self.domain_file = domain_file
        self.create()

    def create(self):
        self.table_model = VersionHistoryTableModel([Version(0)])
        self.table = tk.GTable(self.table_model)
        sp = tk.JScrollPane(self.table)
        self.add(sp)

    def add(self, widget):
        self.config(bg='SystemButtonFace')
        self.pack(fill=tk.BOTH, expand=1)
        self.add(widget)

    def set_domain_file(self, domain_file):
        if domain_file is not None:
            self.domain_file = domain_file
            self.refresh()

    def refresh(self):
        try:
            history = self.domain_file.get_version_history()
            self.table_model.refresh(history)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def get_domain_file(self):
        return self.domain_file

    def open_with(self, tool_name):
        row = self.table.get_selected_row()
        if row >= 0:
            version = self.table_model.get_version_at(row)
            domain_object = self.tool.execute_task(version.version, True)
            if domain_object is not None:
                if tool_name is not None:
                    self.tool.launch_tool(tool_name, domain_object.domain_file)
                else:
                    self.tool.launch_default_tool(domain_object.domain_file)

    def open(self):
        self.open_with(None)

class VersionHistoryTableModel:
    VERSION = 0
    DATE = 1
    COMMENTS = 2

    def __init__(self, versions):
        self.versions = versions

    def get_version_at(self, row):
        return self.versions[row]

    def refresh(self, history):
        self.versions = history

class Version:
    def __init__(self, version_number):
        self.version = version_number
```

Please note that this is a simplified translation and some parts of the code might not work as expected in Python due to differences between Java and Python syntax and semantics.