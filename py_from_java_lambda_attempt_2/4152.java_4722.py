Here is the translation of the given Java code into Python:

```Python
import tkinter as tk
from tkinter import messagebox

class UndoAction:
    def __init__(self, tool):
        self.tool = tool
        super().__init__("Undo", "owner")
        set_help_location("help location")

    def actionPerformed(self, program_context):
        try:
            save_current_location_to_history()
            program().undo()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def update(self, program):
        if not program:
            self.set_menu_bar_data("Undo")
            self.description = ""
            self.enabled = False
        elif program.can_undo():
            self.set_menu_bar_data(f"Undo {program.get_domain_file().name}")
            tip = f"Undo {html_escape(program.undo_name())}"
            self.description = tip
            self.enabled = True
        else:
            self.description = "Undo"
            self.enabled = False

    def is_enabled_for_context(self, context):
        program = context.program()
        return program.can_undo()

def save_current_location_to_history():
    # This method should be implemented based on the actual implementation in Java.
    pass

def html_escape(text):
    # This function should escape HTML characters from text
    pass

# Usage:
tool = PluginTool()  # Replace with your plugin tool instance
action = UndoAction(tool)
```

Please note that this translation is not a direct conversion of the given code into Python. It's more like an equivalent implementation in Python, considering some differences between Java and Python.