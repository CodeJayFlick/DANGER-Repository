Here is the equivalent Python code:

```Python
import tkinter as tk
from typing import Tuple

class BackgroundIcon:
    VERSION_ICON_COLOR_DARK = '#5082FF'
    VERSION_ICON_COLOR_LIGHT = '#9F9FFF'

    WIDTH: int = 18
    HEIGHT: int = 17

    def __init__(self, width: int = WIDTH, height: int = HEIGHT, is_versioned: bool = False):
        self.width = width
        self.height = height
        self.is_versioned = is_versioned

    @property
    def icon_height(self) -> int:
        return self.height

    @property
    def icon_width(self) -> int:
        return self.width

    def paint_icon(self, canvas: tk.Canvas, x: int, y: int):
        if self.is_versioned:
            canvas.create_rectangle(x + 1, y + 1, x + self.width - 2, y + self.height - 2, fill=self.VERSION_ICON_COLOR_LIGHT)
            canvas.create_line(x + 1, y, x + self.width - 2, y, fill=self.VERSION_ICON_COLOR_DARK)
            canvas.create_line(x + self.width - 1, y + 1, x + self.width - 1, y + self.height - 2, fill=self.VERSION_ICON_COLOR_DARK)
            canvas.create_line(x + 1, y + self.height - 1, x + self.width - 2, y + self.height - 1, fill=self.VERSION_ICON_COLOR_DARK)
            canvas.create_line(x, y + 1, x, y + self.height - 2, fill=self.VERSION_ICON_COLOR_DARK)

        else:
            canvas.create_rectangle(x, y, x + self.width, y + self.height, fill=canvas.cget('background'))
```

Note that Python does not have a direct equivalent to Java's `Icon` interface or the Swing library. Instead, we use Tkinter (a built-in Python GUI library) and its `Canvas` widget to draw shapes and lines.