import tkinter as tk
from PIL import ImageTk, Image

class CloneCodeViewerAction:
    def __init__(self, owner, provider):
        self.provider = provider
        super().__init__("Code Viewer Clone", owner)
        image_path = "images/camera-photo.png"
        image = Image.open(image_path).resize((16, 16), Image.ANTIALIAS)  # Resize the image to fit in toolbar
        icon = ImageTk.PhotoImage(image)
        self.set_icon(icon)

    def set_icon(self, icon):
        self.toolbar_data = tk.Toplevel()
        self.toolbar_data.title("Code Viewer Clone")
        label = tk.Label(self.toolbar_data, image=icon)
        label.pack()

    def description(self):
        return "Create a snapshot (disconnected) copy of this Listing window"

    def help_location(self):
        return {"Snapshots": "Snapshots_Start"}

    def key_binding_data(self):
        return {"key": tk.K_t,
                "modifiers": tk.CONTROL | tk.SHIFT}

    def is_enabled_for_context(self, context):
        if isinstance(context, ProgramActionContext):
            program_context = context
            return program_context.get_program() is not None
        return False

    def action_performed(self, context):
        self.provider.clone_window()

# Example usage:
class CodeViewerProvider:
    def clone_window(self):
        print("Cloning window...")

provider = CodeViewerProvider()
action = CloneCodeViewerAction(None, provider)
