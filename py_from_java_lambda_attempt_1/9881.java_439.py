Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import font

class HexOrDecimalInput:
    def __init__(self):
        self.is_hex_mode = False
        self.allows_negative = True
        self.current_value = None

    def set_decimal_mode(self):
        self.is_hex_mode = False
        self.update_text()

    def set_hex_mode(self):
        self.is_hex_mode = True
        self.update_text()

    def update_text(self):
        if not self.current_value:
            text = ""
        else:
            value = abs(self.current_value)
            if self.is_hex_mode:
                text = hex(value)[2:]
            else:
                text = str(value)

            if self.current_value < 0:
                text = "-" + text

        self.text.set(text)

    def compute_text_for_current_value(self):
        if not self.current_value:
            return ""

        value = abs(self.current_value)
        absolute_value = value
        if value < 0:
            absolute_value = -value

        if self.is_hex_mode:
            text = hex(absolute_value)[2:]
        else:
            text = str(absolute_value)

        if value < 0:
            text = "-" + text

        return text

    def set_allow_negative(self, b):
        self.allows_negative = b
        if not self.allows_negative and self.current_value is not None and self.current_value < 0:
            self.current_value = None
        self.update_text()

class MyDocument(tk.Text):
    def __init__(self, *args, **kwargs):
        tk.Text.__init__(self, *args, **kwargs)
        self.bind("<<Insert>", self.insert_string)

    def insert_string(self, event):
        if not self.get():
            return

        text = self.get(1.0, "end-1c")
        try:
            value = int(text) if not self.is_hex_mode else int(text, 16)
            if self.allows_negative and text.startswith("-"):
                value *= -1
                text = "-" + text[1:]
            elif not self.allows_negative and value < 0:
                return

            self.current_value = value
        except ValueError:
            pass

    def remove(self):
        tk.Text.remove(self)
        if self.get() == "":
            self.current_value = None
        else:
            try:
                self.current_value = int(self.get()) if not self.is_hex_mode else int(self.get(), 16)
            except ValueError:
                pass


class HexOrDecimalInputWidget(tk.Frame):
    def __init__(self, *args, **kwargs):
        tk.Frame.__init__(self, *args, **kwargs)

        self.text = tk.StringVar()
        self.entry = tk.Entry(self, textvariable=self.text)
        self.set_decimal_mode()

        self.pack()


root = tk.Tk()
frame = HexOrDecimalInputWidget(root)
frame.pack()
root.mainloop()
```

Please note that this code is a direct translation of the Java code and may not work exactly as expected in Python. The `GraphicsUtils` class used in the original Java code does not have an equivalent in Python, so I removed it from the translation.