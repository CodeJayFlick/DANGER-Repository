import tkinter as tk
from PIL import Image, ImageDraw, ImageFont

class MultiIconBuilderTest:
    def __init__(self):
        self.font = ImageFont.truetype("Monospaced.ttf", 12)

    def make_empty_icon(self, w, h, color):
        img = Image.new('ARGB', (w, h))
        if color is not None:
            draw = ImageDraw.Draw(img)
            draw.rectangle((0, 0, w, h), fill=color)
        return tk.PhotoImage(img)

    def make_quandrant_icon(self, w, h, bg_color, line_color):
        img = Image.new('ARGB', (w, h))
        draw = ImageDraw.Draw(img)
        draw.rectangle((0, 0, w, h), fill=bg_color)
        draw.line([(w // 2, 0), (w // 2, h)], fill=line_color)
        draw.line([(0, h // 2), (w, h // 2)], fill=line_color)
        return tk.PhotoImage(img)

    def show_icon_text(self):
        for quad in QUADRANT:
            icon = MultiIconBuilder(
                self.make_quandrant_icon(32, 32, Color('gray'), Color('white'))
            ).add_text("Abcfg", self.font, Color('red'), quad).build()
            tk.messagebox.showinfo(f"{quad} aligned", "Icon text overlay test")

    def show_icon_overlay(self):
        for quad in QUADRANT:
            icon = MultiIconBuilder(
                self.make_empty_icon(32, 32, Color('gray'))
            ).add_icon(self.make_quandrant_icon(8, 8, Color('red'), Color('black')), 8, 8, quad).build()
            tk.messagebox.showinfo(f"{quad} aligned", "Icon icon overlay test")

    def show_scaled_icon_overlay(self):
        for quad in QUADRANT:
            icon = MultiIconBuilder(
                self.make_empty_icon(32, 32, Color('gray'))
            ).add_icon(self.make_quandrant_icon(32, 32, Color('red'), Color('black')), 14, 14, quad).build()
            tk.messagebox.showinfo(f"{quad} aligned", "Scaled icon icon overlay test")

    def test_icon_overlay(self):
        for quad in QUADRANT:
            icon = MultiIconBuilder(
                self.make_empty_icon(32, 32, Color('gray'))
            ).add_icon(self.make_quandrant_icon(32, 32, Color('red'), Color('black')), 14, 14, quad).build()
            print(icon)

    def test_icon_text(self):
        for quad in QUADRANT:
            icon = MultiIconBuilder(
                self.make_quandrant_icon(32, 32, Color('gray'), Color('white'))
            ).add_text("Abcfg", self.font, Color('red'), quad).build()
            print(icon)

class Color:
    def __init__(self, color):
        self.color = color

QUADRANT = ['TopLeft', 'TopRight', 'BottomLeft', 'BottomRight']

if __name__ == "__main__":
    test = MultiIconBuilderTest()
    #test.show_icon_text()
    #test.show_icon_overlay()
    #test.show_scaled_icon_overlay()
    #test.test_icon_overlay()
    #test.test_icon_text()

