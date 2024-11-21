Here is the translation of the Java code to Python:
```
import tkinter as tk
from PIL import ImageTk, Image

class LabelTestVertex:
    def __init__(self, name):
        self.name = name
        self.label = tk.Label(text=name)
        self.label.config(width=50, height=50, bg='yellow', borderwidth=1, relief="ridge", anchor=tk.CENTER)

    def get_component(self):
        return self.label

# Example usage:
test_vertex = LabelTestVertex("Hello World")
```
Note that I used the `tkinter` library for creating GUI components in Python. The equivalent of Java's Swing is not available in standard Python, so we use a third-party library like Tkinter or PyQt to create graphical user interfaces.

Also, there is no direct equivalent of Java's JLabel and JComponent classes in Python. Instead, I used the `tk.Label` class from Tkinter to create a label component that can be used as a vertex in your graph visualization application.