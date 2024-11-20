Here is a translation of your Java code into equivalent Python:

```Python
import tkinter as tk
from tkinter import messagebox
from typing import List, Set

class ImportGhidraToolsDialog:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Import Ghidra Tools")
        self.main_panel = tk.Frame(self.root)
        self.list_panel = tk.Listbox(self.main_panel)
        self.checkboxes = []
        self.tools = []

    def create_panel(self) -> None:
        self.main_panel.pack(fill=tk.BOTH, expand=1)

        button_frame = tk.Frame(self.main_panel)
        select_all_button = tk.Button(button_frame, text="Select All", command=self.select_all)
        deselect_all_button = tk.Button(button_frame, text="Deselect All", command=self.deselect_all)
        button_frame.pack(side=tk.LEFT)

        self.list_panel.pack(fill=tk.BOTH, expand=1)

    def add_listeners(self) -> None:
        select_all_button = self.main_panel.winfo_children()[0].winfo_children()[0]
        deselect_all_button = self.main_panel.winfo_children()[0].winfo_children()[1]

        select_all_button.bind("<Button-1>", lambda event: self.select_all())
        deselect_all_button.bind("<Button-1>", lambda event: self.deselect_all())

    def load_list_data(self) -> None:
        default_tools = ["Tool 1", "Tool 2"]
        extra_tools = ["Extra Tool 1", "Extra Tool 2"]

        for tool in default_tools + extra_tools:
            checkbox = tk.Checkbutton(self.list_panel, text=tool)
            self.checkboxes.append(checkbox)

    def select_all(self) -> None:
        for i, _ in enumerate(self.checkboxes):
            self.checkboxes[i].select()

    def deselect_all(self) -> None:
        for i, _ in enumerate(self.checkboxes):
            self.checkboxes[i].deselect()

    def get_selected_list(self) -> List[str]:
        selected_tools = []
        for checkbox in self.checkboxes:
            if checkbox.instate()[0] == tk.ACTIVE:
                selected_tools.append(checkbox.cget("text"))
        return selected_tools

    def is_cancelled(self) -> bool:
        return False  # You can implement this method as needed.

    def run(self):
        self.create_panel()
        self.add_listeners()
        self.load_list_data()

        self.root.mainloop()

if __name__ == "__main__":
    dialog = ImportGhidraToolsDialog()
    dialog.run()
```

Please note that the above Python code is a translation of your Java code and may not be exactly equivalent. The `JPanel`, `JButton`, `ListPanel` classes in Java do not have direct equivalents in Python, so I used Tkinter widgets to achieve similar functionality.