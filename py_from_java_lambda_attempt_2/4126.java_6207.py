Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from PIL import Image, ImageDraw
import math

class KnotLabelPanel:
    def __init__(self, top_bottom_margin):
        self.top_bottom_margin = top_bottom_margin
        self.palette = None

    def set_palette(self, palette):
        self.palette = palette

    def paint_component(self, g):
        super().paint_component(g)

        g2d = tk.Canvas.create_window(g)
        g2d.setRenderingHint(0, 1) # equivalent to RenderingHints.VALUE_ANTIALIAS_ON in Java

        height = g.winfo_height() - 2 * self.top_bottom_margin
        width = g.winfo_width()
        g.itemconfigure('background', fill=g.get_background())
        g.create_rectangle(0, 0, width, height)

        palette_size = len(self.palette)
        font = tk.font.Font(family='Times New Roman', size=16, weight=tk.BOLD)
        ascent = font.metrics()['ascent']
        descent = font.metrics()['descent']
        font_offset = math.ceil(ascent / 3) # equivalent to ascent/3 in Java

        for record in self.palette:
            start = (record.start * height) // palette_size
            end = (record.end * height) // palette_size
            y = self.top_bottom_margin + ((start + end) // 2)
            g.create_text(20, y + font_offset, text=self.get_label(record), font=font)

    def get_label(self, record):
        return f"{record.name}"

# Example usage:
palette = ['Record1', 'Record2'] # replace with your actual palette
panel = KnotLabelPanel(top_bottom_margin=10)
panel.set_palette(palette)
```

Please note that Python does not have direct equivalent of Java's `Graphics` and `FontMetrics`. We used the Tkinter library to create a canvas for drawing, which is different from Java's Graphics.