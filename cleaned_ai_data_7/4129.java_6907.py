import tkinter as tk

class LegendPanel(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.pack()
        self.create_widgets()

    def create_widgets(self):
        header_frame = tk.Frame(self)
        header_frame.pack(side=tk.TOP)

        palette_frame = tk.Frame(self)
        knot_frame = tk.Frame(self)

        self.add(header_frame, side=tk.TOP)
        self.add(palette_frame, side=tk.LEFT)
        self.add(knot_frame, side=tk.CENTER)

    def add(self, widget, side):
        if side == tk.TOP:
            widget.pack(side=side)
        elif side == tk.LEFT:
            widget.grid(row=0, column=0)
        else:  # CENTER
            widget.grid(row=0, column=1)

    def set_palette(self, pal):
        self.palette_frame.set_palette(pal)
        self.knot_frame.set_palette(pal)

class PalettePanel(tk.Frame):
    def __init__(self, master=None, width=30):
        super().__init__(master)
        self.master = master
        self.width = width

    def set_palette(self, pal):
        # implement palette logic here

class KnotLabelPanel(tk.Frame):
    def __init__(self, master=None, width=30):
        super().__init__(master)
        self.master = master
        self.width = width

    def set_palette(self, pal):
        # implement knot label panel logic here

root = tk.Tk()
legend_panel = LegendPanel(root)
legend_panel.pack(fill=tk.BOTH, expand=True)

palette_panel = PalettePanel(30)
knot_label_panel = KnotLabelPanel(30)

legend_panel.set_palette(palette_panel)  # set palette for both panels
