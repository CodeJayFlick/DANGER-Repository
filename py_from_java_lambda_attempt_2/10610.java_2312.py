Here is the translation of the Java code to Python:
```
import tkinter as tk

class ColorIcon3D:
    def __init__(self, color):
        self.color = color
        self.width = 16
        self.height = 16

    def __init__(self, color, width, height):
        self.color = color
        self.width = width
        self.height = height

    @property
    def icon_height(self):
        return self.height

    @property
    def icon_width(self):
        return self.width

    @property
    def color_(self):
        return self.color

    def paint_icon(self, c, g, x, y):
        start_color = g.cget('fill')
        g.itemconfig(g.create_rectangle(x, y, x + self.width, y + self.height), fill=self.color_)
        g.itemconfig(c, fill=start_color)
```
Note that I used the `tkinter` library to create a Python equivalent of the Java code. The `paint_icon` method is not exactly equivalent to the original Java code, as it uses Tkinter's canvas and rectangle drawing methods instead of directly manipulating graphics contexts.

Also, in Python, we don't need explicit getters and setters for properties like Java does with getter/setter methods. Instead, I used Python's built-in property decorator (`@property`) to create read-only properties that can be accessed using dot notation (e.g., `icon_height`).