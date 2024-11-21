import tkinter as tk
from tkinter import filedialog
from PIL import Image, ImageOps

class SaveImageAction:
    def __init__(self, owner, image_panel):
        self.owner = owner
        self.image_panel = image_panel
        self.name = "Export Image"
        self.toolbar_data = ResourceManager.load_image("images/disk_save_as.png")

    def get_export_file(self):
        file_path = filedialog.asksaveasfilename(title="Export Image As...", defaultextension=".png", filetypes=[("Image Files", ".png .jpg .gif")])
        return file_path

    def get_extension_from_file(self, file_name):
        name = file_name
        ext_pos = name.rfind('.')
        if ext_pos < 0:
            return "png"
        else:
            return name[ext_pos:]

    def export_image(self, image, file_name):
        buffered = ImageOps.get_buffered(image)
        extension = self.get_extension_from_file(file_name).lower()
        if extension in ["png", "gif", "jpg"]:
            pass
        else:
            extension = "png"
        try:
            buffered.save(file_name, format=extension.upper())
            print(f"Saved image to '{file_name}' in {extension.upper()} format")
        except Exception as e:
            print(f"Unable to save image to '{file_name}': {str(e)}")

    def action_performed(self):
        file_path = self.get_export_file()
        if not file_path:
            return
        try:
            self.export_image(self.image_panel.get_image(), file_path)
        except Exception as e:
            print(f"Unable to save image to '{file_path}': {str(e)}")

# Usage example:

image_panel = ImagePanel()  # Replace with your actual image panel object.
action = SaveImageAction("owner", image_panel)  # Replace "owner" and `image_panel` with the correct values.

if __name__ == "__main__":
    action.action_performed()
