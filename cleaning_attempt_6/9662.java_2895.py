import tkinter as tk
from PIL import ImageTk, Image

class ZoomResetAction:
    ZOOM_ICON = None  # Initialize with None

    def __init__(self, owner, image_panel):
        self.owner = owner
        self.image_panel = image_panel
        super().__init__("Reset Zoom", owner)

        if not hasattr(self.__class__, 'ZOOM_ICON'):
            from resources import ResourceManager
            self.ZOOM_ICON = ResourceManager.load_image("images/zoom.png")

    def is_enabled_for_context(self, context):
        return (super().is_enabled_for_context(context) and 
                self.image_panel.get_zoom_factor() != self.image_panel.get_default_zoom_factor())

    def action_performed(self, context):
        self.image_panel.reset_zoom()

class ImagePanel:
    def __init__(self):
        pass

    def get_zoom_factor(self):
        return 1.0  # Default zoom factor

    def set_zoom_factor(self, value):
        pass

    def reset_zoom(self):
        pass

    def get_default_zoom_factor(self):
        return self.get_zoom_factor()

class ResourceManager:
    @staticmethod
    def load_image(path):
        from PIL import ImageTk, Image
        img = Image.open(path)
        return ImageTk.PhotoImage(img)

# Example usage:

if __name__ == "__main__":
    owner = "Your Owner"
    image_panel = ImagePanel()
    
    action = ZoomResetAction(owner, image_panel)
