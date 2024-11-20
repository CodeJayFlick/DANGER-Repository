Here is the translation of the Java code to Python:
```python
import tkinter as tk
from ghidra.util.filechooser import GhidraFileChooserModel

class FileTableCellRenderer:
    def __init__(self, chooser):
        self.model = chooser.get_model()
        self.chooser = chooser

    def get_table_cell_renderer_component(self, data):
        file = data['value']
        data['cell_data'] = (self.chooser.get_display_name(file), 
                             data['column_view_index'], 
                             data['selected'], 
                             data['has_focus'])
        c = super().get_table_cell_renderer_component(data)

        if isinstance(c, tk.Label):
            c.config(image=self.model.get_icon(file))
        return c
```
Note that I used the `tkinter` library to create a Python equivalent of the Java code. Specifically:

* The `Component` class in Java is replaced with `tk.Label`, which is a subclass of `tk.Widget`.
* The `GTableCellRenderer` and `GTableCellRenderingData` classes are not directly translatable, so I used the `super()` function to call the parent class's method.
* The `getTableCellRendererComponent` method is renamed to `get_table_cell_renderer_component`, following Python's convention for method names.

Also note that this code assumes you have a `GhidraFileChooserModel` object available, which is not provided in your original Java code. You would need to create an instance of this class or import it from another module before using it in the above Python code.