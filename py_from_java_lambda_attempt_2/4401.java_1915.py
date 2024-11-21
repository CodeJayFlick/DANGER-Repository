Here is the translation of the Java code to Python:
```python
import tkinter as tk
from tkinter import ttk

class SymbolEditor:
    def __init__(self):
        self.symbol_field = None
        super().__init__()

    @property
    def symbol_field(self):
        if not hasattr(self, '_symbol_field'):
            self._symbol_field = tk.Entry()
            self._symbol_field.setBorder(0)  # equivalent to createEmptyBorder() in Java
        return self._symbol_field

    def get_cell_editor_value(self):
        return self.symbol_field.get().strip()

    def get_table_cell_editor_component(self, table, value, selected, row, column):
        if isinstance(value, dict):  # assuming Symbol is a dictionary-like object
            symbol = value['name']
        else:
            symbol = None

        self.symbol_field.delete(0, tk.END)
        if symbol:
            self.symbol_field.insert(tk.END, symbol)
        return self.symbol_field
```
Note that I used the `tkinter` library (which is Python's equivalent of Java's Swing) to create a GUI component. The rest of the code was translated as closely as possible from Java to Python.

Here are some key differences:

* In Java, you need to explicitly call the superclass constructor (`super()`), whereas in Python, you don't.
* In Java, `JTextField` is equivalent to `tk.Entry` in Python.
* In Java, `BorderFactory.createEmptyBorder()` is equivalent to setting the border of a GUI component to 0 (zero) using `setBorder(0)` in Python.

Please note that this code assumes that you have some basic understanding of Python and its libraries.