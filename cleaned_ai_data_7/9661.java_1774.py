import tkinter as tk
from PIL import ImageTk, Image

class ZoomOutAction:
    ZOOM_OUT_ICON = None  # Initialize icon variable

    def __init__(self, owner, image_panel):
        self.owner = owner
        self.image_panel = image_panel

        super().__init__("Zoom Out", owner)

        menu_data = {"items": ["Zoom out"], "category": "view"}
        tool_bar_data = (ZOOM_OUT_ICON,)

        set_popup_menu(menu_data)
        set_tool_bar(tool_bar_data)

    def is_enabled_for_context(self):
        if not super().is_enabled_for_context():
            return False
        return self.image_panel.can_zoom_out()

    def action_performed(self):
        self.image_panel.zoom_out()


class ImagePanel:
    def __init__(self, owner):
        self.owner = owner

    def can_zoom_out(self):
        # Add your logic here to check if the image panel can zoom out
        return True  # Default value for demonstration purposes only

    def zoom_out(self):
        # Add your logic here to perform a zoom-out action on the image panel
        pass


class ResourceManager:
    @staticmethod
    def load_image(icon_name):
        # Load an icon from resources based on the given name
        return ImageTk.PhotoImage(Image.open(f"images/{icon_name}.png"))


# Example usage:

if __name__ == "__main__":
    owner = "Your Owner"
    image_panel = ImagePanel(owner)

    zoom_out_action = ZoomOutAction(owner, image_panel)
