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
