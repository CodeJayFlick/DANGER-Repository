Here is a translation of the Java code into equivalent Python:

```Python
import tkinter as tk
from PIL import ImageTk, Image

class HourglassAnimationPanel:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Hourglass Animation")
        
        # Create an empty list to store icons
        icon_list = []
        
        for i in range(1, 12):  # Assuming there are 11 images from hourglass24_01.png to hourglass24_11.png
            image_path = f"images/hourglass24_{i:02d}.png"
            img = Image.open(image_path)
            icon_list.append(ImageTk.PhotoImage(img))
        
        self.progress_icon = tk.Label(self.root, image=icon_list[0])
        self.progress_icon.pack(side=tk.TOP)

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    panel = HourglassAnimationPanel()
    panel.run()
```

This Python code uses the `tkinter` library for creating a GUI and displaying images. It also assumes that you have 11 PNG files named "hourglass24_01.png" to "hourglass24_11.png" in an "images" directory, which are used as icons for the animation.

Please note that this is not exactly equivalent code since Python does not support multi-threading like Java's Swing library.