import tkinter as tk
from PIL import Image, ImageTk

class SpacecurveRasterPanel:
    def __init__(self):
        self.raster = None
        self.width = 0
        self.height = 0
        self.color_model = None

    def set_raster(self, raster, width, height):
        if len(raster) != width * height:
            raise ValueError("raster length must be equal to width times height")
        self.raster = raster
        self.width = width
        self.height = height
        self.update()

    def update(self):
        img = Image.frombytes('L', (self.width, self.height), bytes(self.raster))
        photo = ImageTk.PhotoImage(img)
        self.canvas.create_image(0, 0, anchor='nw', image=photo)

class Application(tk.Frame):

    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.pack()
        self.create_widgets()

    def create_widgets(self):
        panel = SpacecurveRasterPanel()
        frame = tk.Frame(self)
        frame.pack(side="top")
        panel.set_raster(bytearray([i % 256 for i in range(65536)]), 256, 256)

app = Application(master=tk.Tk())
app.mainloop()
