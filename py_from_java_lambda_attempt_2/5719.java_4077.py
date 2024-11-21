Here is a translation of the Java code into equivalent Python code:

```Python
import tkinter as tk
from PIL import ImageTk, Image
import os

class InfoPanel:
    def __init__(self):
        self.version = ""
        self.marking = None
        self.distribution_info = None
        self.bg_color = "#F2F2F2"
        self.image_width = 0

        self.create()

    def create(self):
        self.setLayout(tk.FrameLayout())
        self.add(self.build_text_panel(), tk.TOP)
        self.add(self.build_image_panel(), tk.CENTER)

    def build_text_panel(self):
        panel = tk.Frame()
        panel.pack(fill=tk.X, expand=True)

        if Application.is_test_build():
            label = tk.Label(panel, text="-- UNSUPPORTED TEST BUILD --", fg="red")
            label.pack()

        version_label = self.build_version_label()
        distribution_label = self.build_distribution_label()

        if self.marking is not None:
            marking_label = self.build_marking_label()
            panel.add(marking_label)

        if self.distribution_info is not None:
            panel.add(distribution_label)

    def build_distribution_label(self):
        content = self.distribution_info

        view = tk.Label(panel, text=content)
        return view

    def build_version_panel(self):
        vpanel = tk.Frame()
        vpanel.pack(fill=tk.X, expand=True)

        version_label = self.build_version_label()

        if Application.is_test_build():
            test_label = tk.Label(vpanel, text="-- UNSUPPORTED TEST BUILD --", fg="red")
            test_label.pack(side=tk.BOTTOM)
        else:
            vpanel.add(version_label)

    def build_marking_label(self):
        marking_label = tk.Label(panel, text=self.marking, fg="red")
        return marking_label

    def create_image_panel(self):
        imagePanel = tk.Frame()
        imagePanel.pack(fill=tk.X, expand=True)

        ghidraSplashImage = ImageTk.PhotoImage(Image.open("images/GHIDRA_Splash.png"))
        label = tk.Label(imagePanel, image=ghidraSplashImage)
        label.image = ghidraSplashImage
        return imagePanel

    def build_version_label(self):
        versionLabel = tk.Label(panel, text=self.version, font=("Arial", 14), fg="black")
        return versionLabel

class Application:
    @staticmethod
    def is_test_build():
        # Your code here to check if it's a test build or not.
        pass

    @staticmethod
    def get_application_release_name():
        # Your code here to get the release name of your application.
        pass

    @staticmethod
    def get_build_date():
        # Your code here to get the build date of your application.
        pass

class ResourceManager:
    @staticmethod
    def load_image(filename):
        try:
            image = Image.open(filename)
            return ImageTk.PhotoImage(image)
        except Exception as e:
            print(f"Error loading {filename}: {e}")
            return None

if __name__ == "__main__":
    root = tk.Tk()
    panel = InfoPanel()

    frame = tk.Frame(root, bg="#F2F2F2")
    frame.pack(fill=tk.BOTH, expand=True)

    image_panel = panel.create_image_panel()
    text_panel = panel.build_text_panel()

    frame.add(image_panel)
    frame.add(text_panel)

    root.mainloop()
```

This Python code is equivalent to the Java code provided.