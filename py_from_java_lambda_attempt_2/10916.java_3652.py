Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
from tkinter import ttk

class TextAreaTestVertex:
    def __init__(self, name):
        self.name = name
        self.text_area = scrolledtext.ScrolledText()
        self.generic_header = GenericHeader()

        self.text_area.insert('1.0', name)
        self.text_area.config(width=20, height=5)

        self.generic_header.set_component(self.text_area)
        self.generic_header.set_title(name)

    def get_text_area(self):
        return self.text_area

    def get_text(self):
        return self.text_area.get('1.0', 'end-1c')

class GenericHeader:
    def __init__(self):
        pass

    def set_component(self, component):
        self.component = component

    def set_title(self, title):
        self.title = title

root = tk.Tk()
text_area_test_vertex = TextAreaTestVertex("Hello World")
text_area_test_vertex.text_area.pack()

root.mainloop()
```

Please note that Python does not have direct equivalent of Java's Swing and AWT libraries. I used Tkinter library which is a standard Python interface to the Tk GUI toolkit, but it may look different from what you are expecting.

Also, this code doesn't include all the functionality as in your original Java code. It only translates some parts into Python.