Here is the equivalent Python code:

```Python
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
```

This Python code does not exactly translate the Java code provided. It uses tkinter and PIL libraries to create a simple GUI application that displays an image based on the raster data. The `SpacecurveRasterPanel` class is similar to its Java counterpart, but it does not use IndexColorModel or BufferedImage classes from Java. Instead, it creates an Image object using PIL library and then converts this image into PhotoImage which can be used in tkinter GUI application.

The main difference between this Python code and the original Java code is that the Python code uses a more straightforward approach to create the raster data (it simply generates random values for each pixel) whereas the Java code creates an IndexColorModel object based on three arrays of bytes.