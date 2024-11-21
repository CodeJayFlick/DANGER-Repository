import tkinter as tk
from tkinter import messagebox

class SelectEndOfLineAction:
    KEY_STROKE = "end"
    ACTION_NAME = "selection-end-line"

    def __init__(self):
        pass

    def error(self, component):
        if isinstance(component, tk.Text):
            component.focus_set()
            component.selection_range(0, len(component.get("1.0", "end-1c")))

    def get_text_component(self, event):
        return None  # equivalent to null in Java

    def actionPerformed(self, event):
        text_component = self.get_text_component(event)
        if text_component is not None:
            try:
                dot = text_component.index("1.0") + len(text_component.get("1.0", "end-1c"))
                end_position = text_component.index(f"1.{dot}lineend")
                text_component.mark_set("insert", f"{end_position}")
            except tk.TclError as e:
                self.error(text_component)

if __name__ == "__main__":
    pass
