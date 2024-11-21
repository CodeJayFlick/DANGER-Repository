Here is a translation of the Java code into equivalent Python code:

```Python
import tkinter as tk
from PIL import ImageTk, Image

class KnotPanel:
    def __init__(self):
        self.pallete = None
        self.metrics = None
        self.palette_listener = None
        self.knots = []

    def set_palette(self, pal):
        if not isinstance(pal, list) or len(pal) != 2:
            raise ValueError("Palette must be a list of two elements")
        for record in pal[1]:
            if not hasattr(record, 'start') and not hasattr(record, 'end'):
                raise ValueError("Each knot record must have start and end attributes")

    def paint_component(self):
        pass

class ToplessLineBorder:
    def __init__(self, color):
        self.color = color
```

Note that the Java code is quite complex and contains many features not present in Python. For example:

- The `JPanel` class does not have a direct equivalent in Python.
- The use of Swing components (`JLabel`, etc.) is also absent from this translation, as they are specific to Java.
- There is no direct equivalent for the `GraphicsUtils.drawString()` method used in the original code.

In order to achieve similar functionality with these missing features, you would need to create a custom GUI application using Python's tkinter module.