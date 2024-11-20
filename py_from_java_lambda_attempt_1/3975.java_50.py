Here is a translation of the Java code into equivalent Python code:

```Python
import tkinter as tk
from tkinter import ttk

class InstructionSearchMainPanel:
    def __init__(self, plugin, dialog):
        self.search_data = dialog.get_search_data()
        
        if not self.search_data:
            raise InvalidInputException("Search data object cannot be null")

        operands = self.search_data.max_num_operands
        
        instruction_table_panel = InstructionTablePanel(operands, plugin, dialog)
        preview_table_panel = PreviewTablePanel(1, plugin, dialog)

        link_scroll_panes(instruction_table_panel.scrollpane, preview_table_panel.scrollpane)
        
        splitter = split_panels(instruction_table_panel.workpanel, preview_table_panel)
        
        self.frame = tk.Frame()
        self.frame.pack(fill=tk.BOTH, expand=1)
        self.frame.add(splitter, side=tk.TOP)

    def get_preview_table(self):
        return preview_table_panel.table

    def get_instruction_table(self):
        return instruction_table_panel.table


class PreviewTable:
    pass  # This class is not implemented in the original Java code.


def link_scroll_panes(panel1, panel2):
    model = panel1.vertical_bar.get()
    panel2.vertical_bar.set(model)


def split_panels(panel1, panel2):
    splitter = tk.Splitter(orient=tk.HORIZONTAL)
    splitter.add(panel1, panel2)

    return splitter


class InvalidInputException(Exception):
    pass
```

Please note that Python does not have a direct equivalent to Java's Swing library. The above code uses the tkinter module for creating GUI components like frames and panels.