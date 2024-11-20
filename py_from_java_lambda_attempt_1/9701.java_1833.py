Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import scrolledtext
from tkinter import filedialog
from tkinter import messagebox

class ScrollableTextArea:
    def __init__(self):
        self.text_area = scrolledtext.ScrolledText()
        self.initialize()

    def initialize(self):
        self.text_area.set_line_wrap(False)
        self.set_autoscrolls(True)

    def set_caret_position(self, position):
        self.text_area.insert('end', '\n' * (position + 1))

    def get_text_visible_height(self):
        return int(self.text_area.get('1.0', 'end-1c').count('\n') + 1) * 20

    def set_tab_size(self, tab_size):
        self.text_area.set_tabs_to_spaces(tab_size)

    def append(self, text):
        self.text_area.insert('end', text)
        self.text_area.see(tk.END)

    def insert(self, position, text):
        self.text_area.insert(position, text)

    def replace_range(self, start, end, text):
        self.text_area.delete(start, end)
        self.text_area.insert(start, text)

    def set_text(self, text):
        self.text_area.delete('1.0', 'end-1c')
        self.text_area.insert('1.0', text)

    def get_text(self):
        return self.text_area.get('1.0', 'end-1c')

    def set_editable(self, editable):
        self.text_area.config(state='normal' if editable else 'disabled')


class PrivateTextArea(scrolledtext.ScrolledText):
    pass


if __name__ == "__main__":
    root = tk.Tk()
    text_area = ScrollableTextArea()

    # Create a frame to hold the text area
    frame = tk.Frame(root)
    frame.pack(fill='both', expand=True)

    # Add the text area to the frame
    text_area.text_area.pack(expand=True, fill='both')

    root.mainloop()
```

Please note that this is not an exact translation of your Java code. Python's tkinter library does not have a direct equivalent for some of the methods and classes used in your original code (e.g., `JPopupMenu`, `TransferHandler`, etc.). This code provides basic functionality similar to what you had, but it may need further modifications based on specific requirements.