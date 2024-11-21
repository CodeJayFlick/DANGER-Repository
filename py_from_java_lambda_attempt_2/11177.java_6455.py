Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from PIL import Image, ImageTk

class ZoomedImagePainter:
    def __init__(self, target_bounds, image):
        self.target_bounds = target_bounds
        self.image = image
        self.zoom = 0.0
        self.magnify_factor = 10.0

    def paint(self, glass_pane, canvas):
        if not self.image or not self.target_bounds:
            return
        
        # the width is based upon the magnify factor and the 
        # zoom (set by the animator's progress)
        image_width = self.image.width
        width = int(image_width + (image_width * self.magnify_factor * self.zoom))

        # the height is also based upon the magnify factor and the 
        # zoom (set by the animator's progress)
        image_height = self.image.height
        height = int(image_height + (image_height * self.magnify_factor * self.zoom))

        # calculate the coordinates, centering the image drawing over the container' bounds
        middle_bounds_x = self.target_bounds.width // 2
        middle_bounds_y = self.target_bounds.height // 2
        middle_width_x = width // 2
        middle_height_y = height // 2
        x = middle_bounds_x - middle_width_x + self.target_bounds.x
        y = middle_bounds_y - middle_height_y + self.target_bounds.y

        canvas.create_image(x, y, image=self.image)

    def get_zoom(self):
        return self.zoom

    # callback for timing framework
    def set_zoom(self, zoom):
        self.zoom = zoom

    def get_target_bounds(self):
        return self.target_bounds

    # callback for timing framework
    def set_target_bounds(self, container_bounds):
        self.target_bounds = container_bounds

    def set_magnify_factor(self, factor):
        self.magnify_factor = factor


def create_icon_image(icon):
    buff_image = Image.new('RGBA', (icon.width(), icon.height()))
    graphics = ImageDraw.Draw(buff_image)
    icon.paint(graphics, 0, 0)
    return buff_image
```

This Python code uses the `tkinter` library for GUI operations and PIL (Python Imaging Library) to handle image manipulation.