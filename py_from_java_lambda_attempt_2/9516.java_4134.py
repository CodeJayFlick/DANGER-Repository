Here is a translation of the Java code into equivalent Python code:

```Python
import tkinter as tk
from tkinter import simpledialog

class InputDialog:
    def __init__(self, title, labels=None, initial_values=None):
        self.is_canceled = False
        if not labels:
            labels = [""]
        if not initial_values:
            initial_values = [""]

        self.text_fields = []
        for i in range(len(labels)):
            text_field = tk.Entry(root, width=20)
            text_field.insert(0, initial_values[i])
            self.text_fields.append(text_field)

    def show(self):
        for field in self.text_fields:
            field.pack()
        ok_button = tk.Button(root, text="OK", command=self.ok_callback)
        cancel_button = tk.Button(root, text="Cancel", command=root.destroy)
        ok_button.pack()
        cancel_button.pack()

        root.mainloop()

    def ok_callback(self):
        for i in range(len(self.text_fields)):
            self.text_values[i] = self.text_fields[i].get().strip()
        if not self.listener or self.listener.input_is_valid():
            self.close()

    def close(self):
        root.destroy()

class MyListener:
    def input_is_valid(self, dialog):
        return True

root = tk.Tk()
dialog = InputDialog("Testing Dialog 1", ["Enter project name:"])
dialog.show()
```

Please note that this code is not a direct translation of the Java code. The Python version uses tkinter for GUI operations and does not include some features like KeyListener, DocumentListener etc., which are specific to Swing in Java.