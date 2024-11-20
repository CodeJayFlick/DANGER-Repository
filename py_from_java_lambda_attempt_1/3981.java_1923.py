Here is the translation of the Java code to Python:
```python
import tkinter as tk
from typing import Any

class PreviewTablePanel:
    def __init__(self, columns: int, plugin: Any, dialog: Any):
        self.plugin = plugin
        self.columns = columns
        self.dialog = dialog
        self.setup()

    def build_preview(self) -> None:
        self.preview_table.build_preview_strings()

    @property
    def scroll_pane(self) -> tk.Scrollbar:
        return self.scroll_pane

    @property
    def table(self) -> Any:
        return self.table

    def setup(self) -> None:
        root = tk.Tk()
        frame = tk.Frame(root)
        frame.pack()

        self.preview_table = PreviewTable(columns, plugin, dialog)
        scroll_pane = tk.Scrollbar(frame, orient=tk.HORIZONTAL)
        table = tk.Text(frame)

        scroll_pane.config(command=table.yview)
        table.config(yscrollcommand=scroll_pane.set)

        frame.grid(row=0, column=0, sticky='nsew')
        root.mainloop()

class PreviewTable:
    def __init__(self, columns: int, plugin: Any, dialog: Any):
        self.columns = columns
        self.plugin = plugin
        self.dialog = dialog

    def build_preview_strings(self) -> None:
        # implement this method in Python equivalent of Java code
        pass

class InstructionSearchDialog:
    pass  # implement this class in Python equivalent of Java code

# usage example
plugin = "your_plugin_instance"
dialog = "your_dialog_instance"
columns = 10
panel = PreviewTablePanel(columns, plugin, dialog)
```
Note that I used the `tkinter` library to create a GUI panel, as there is no direct equivalent in Python for Java's Swing or AWT libraries. Additionally, some methods and variables have been renamed or reorganized to conform to Python's syntax and conventions.

Also, please note that this translation assumes you want to keep the same functionality as the original Java code. If you need further modifications or adjustments, let me know!