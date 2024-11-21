Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import filedialog
from tkinter.messagebox import showerror

class FileEditor:
    def __init__(self, chooser):
        self.chooser = chooser
        self.icon_label = tk.Label()
        self.name_field = tk.Entry()

        self.original_file = None
        self.edited_file = None

        self.editor = tk.Frame(self)
        self.editor.pack(fill='both', expand=True)

    def get_table_cell_editor_component(self, table, value, selected, row, column):
        if not selected:
            return self.editor

        self.edited_file = None
        self.original_file = self.chooser.model.get_file(row)
        name = self.original_file.name
        icon = self.chooser.model.get_icon(self.original_file)
        self.icon_label.config(image=icon)
        self.name_field.delete(0, tk.END)
        self.name_field.insert(0, name)

    def get_cell_editor_value(self):
        if not self.edited_file:
            return None

        return self.edited_file
```

Please note that this is a direct translation of the Java code into Python. The original code was written for Swing GUI toolkit in Java and it's hard to directly translate it into Python without using some kind of GUI library like Tkinter or PyQt.