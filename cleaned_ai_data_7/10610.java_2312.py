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
