Here is the translation of the Java code to Python:
```python
import tkinter as tk
from typing import Any

class ApplyEnumDialog:
    def __init__(self, plugin_tool: Any, dtm: Any) -> None:
        self.should_apply_on_sub_ops = False
        super().__init__()

    def create_editor_panel(self, dt_editor: Any) -> Any:
        panel = tk.Frame()
        panel.borderwidth = 5
        panel.padx = 10
        panel.pady = 10

        sub_op_cb = tk.Checkbutton(panel, text="Apply to sub-operands", variable=self.should_apply_on_sub_ops)
        sub_op_cb.pack(side=tk.LEFT)

        label = tk.Label(panel, text="Choose an Enum data type to apply.")
        label.pack()

        dt_editor_component = dt_editor.get_editor_component()
        panel.add(dt_editor_component)
        panel.add(sub_op_cb)

        return panel

    def should_apply_on_sub_ops(self) -> bool:
        return self.should_apply_on_sub_ops
```
Note that I used the `tkinter` library to create a GUI component, as there is no direct equivalent in Python for Java's Swing or AWT libraries. Additionally, I removed some of the boilerplate code and simplified the logic where possible.

Also, please note that this translation assumes you have a basic understanding of both Java and Python programming languages.