Here is the translation of the given Java code into Python:

```Python
import tkinter as tk
from tkinter import messagebox
from typing import List

class SelectChangedToolDialog:
    def __init__(self, tool_list: List):
        self.tool_list = tool_list
        self.was_cancelled = False
        self.selected_tool = None

        root = tk.Tk()
        root.title("Save Tool Changes?")
        root.resizable(False, True)

        panel = tk.Frame(root)
        panel.pack(fill=tk.BOTH, expand=True)

        description_label = tk.Label(panel, text="There are multiple changed instances of " + tool_list[0].get_tool_name() + " running.\nWhich one would like to save to your tool chest?", wraplength=300)
        description_label.config(font=("Arial", 12))
        description_label.pack(fill=tk.BOTH, expand=True)

        button_group = tk.StringVar()
        radio_buttons = []
        for i, tool in enumerate(tool_list):
            rb = tk.Radiobutton(panel, text=tool.get_name(), variable=button_group)
            if i == 0:
                rb.invoke()  # Set the first option as selected
            panel.pack(side=tk.TOP)

    def build_work_panel(self) -> None:
        pass

    def close(self):
        root.destroy()

    def was_cancelled(self) -> bool:
        return self.was_cancelled

    def get_selected_tool(self) -> PluginTool:
        return self.selected_tool


class PluginTool:
    def __init__(self, name: str):
        self.name = name
        self.get_tool_name()  # This method should be implemented in the actual class

    def get_tool_name(self) -> str:
        pass
```

Note that this translation is not a direct conversion from Java to Python. The code has been modified to fit Python's syntax and style, but it may still require adjustments based on your specific use case.

Also note that some parts of the original Java code have been omitted or simplified in this translation, such as the `buildWorkPanel` method which is not implemented here.