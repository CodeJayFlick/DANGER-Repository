Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import ttk

class ExternalConflictInfoPanel:
    def __init__(self):
        self.conflict_type = None
        self.conflict_num = 0
        self.total_conflicts = 0
        self.version_title = None
        self.label_path_name = None
        self.east_label = tk.Label()
        self.west_label = tk.Label()

    def create(self):
        self.root = tk.Tk()
        self.root.title("Resolve External Location Conflict")
        self.frame = ttk.Frame(self.root)
        self.frame.pack(fill="both", expand=True)

        self.west_label.grid(row=0, column=0, sticky=tk.W+tk.E)
        self.east_label.grid(row=0, column=1, sticky=tk.W+tk.E)

    def get_conflict_type(self):
        return self.conflict_type

    def get_label_path_name(self):
        return self.label_path_name

    def set_conflict_type(self, conflict_type):
        self.conflict_type = conflict_type
        self.root.title(f"Resolve {conflict_type} Conflict")

    def set_conflict_info(self, conflict_num, total_conflicts):
        self.conflict_num = conflict_num
        self.total_conflicts = total_conflicts
        self.update_east()

    def update_east(self):
        east_text = f"External Conflict #{self.conflict_num} of {self.total_conflicts}."
        self.east_label.config(text=east_text)

    def set_external_name(self, version_title, label_path_name):
        self.version_title = version_title
        self.label_path_name = label_path_name
        self.update_west()

    def update_west(self):
        west_text = f"Conflict for {self.version_title} version of external {self.label_path_name}."
        self.west_label.config(text=west_text)

if __name__ == "__main__":
    panel = ExternalConflictInfoPanel()
    panel.create()
```

This Python code creates a simple GUI with two labels, one on the west and another on the east. The `ExternalConflictInfoPanel` class represents this GUI. It has methods to set the conflict type, external name, and conflict information.