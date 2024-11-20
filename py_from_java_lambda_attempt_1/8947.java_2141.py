Here is the translation of the Java code to Python:
```
import tkinter as tk

class IntegerFormatterFactory:
    def __init__(self, allows_negative_input=False):
        self.formatter = tk.IntValidator()

    def set_formatter(self, formatter=None, allows_negative_input=False):
        if allows_negative_input:
            self.formatter.set_invalid(True)
        else:
            self.formatter.set_invalid(False)

    def get_formatter(self):
        return self.formatter

# Example usage
factory = IntegerFormatterFactory(allows_negative_input=True)
formatter = factory.get_formatter()
```
Note that I used the `tkinter` library to create a Python equivalent of Java's `JFormattedTextField`. The rest of the code is translated directly from Java to Python.