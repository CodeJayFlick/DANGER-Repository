Here is a translation of the Java code into equivalent Python code:

```Python
import tkinter as tk
from tkinter import messagebox

class DebuggerBreakpointLocEnabledTableCellEditor:
    def __init__(self):
        self.value = False
        self.button = tk.Button()
        self.button.pack()

    def get_cell_editor_value(self):
        return self.value

    def get_table_cell_editor_component(self, table, value, selected, row, column):
        if selected:
            self.button.config(bg=table.selection_background)
        else:
            self.button.config(bg=table.bg)

        self.value = bool(value)  # Assuming the value is a boolean
        icon = DebuggerBreakpointLocEnabledTableCellRenderer.icon_for_enabled(self.value)
        self.button.config(text=str(icon), bg=self.button.cget("bg"))
        return self.button

    def action_performed(self, event):
        if not self.value:
            self.value = True
        else:
            self.value = False
        messagebox.showinfo("Breakpoint", "Breakpoint set")
```

Please note that Python does not have direct equivalent of Java's Swing library. The above code uses tkinter for GUI operations which is a built-in Python module.