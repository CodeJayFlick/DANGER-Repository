import tkinter as tk
from tkinter import colorchooser
from PIL import ImageTk, Image

class ColorEditor:
    LIGHT_COLOR = "silver"
    DARK_COLOR = "black"

    def __init__(self):
        self.preview_label = tk.Label()
        self.color = None
        self.last_user_selected_color = None

        self.preview_label.pack(fill=tk.X)
        self.preview_label.bind("<Button-1>", lambda event: self.show_dialog(event.widget))

    def show_dialog(self, parent_component):
        dialog_panel = tk.Frame(parent_component)
        color_editor_panel = ColorEditorPanel()
        dialog_panel.add(color_editor_panel)

        provider = EditorProvider(dialog_panel)
        docking_window_manager.show_dialog(self.preview_label, provider)

    def get_custom_editor(self):
        return self.preview_label

    def supports_custom_editor(self):
        return True

    def set_value(self, value):
        if isinstance(value, tuple) and len(value) == 4:
            r, g, b, a = value
            color = "#%02x%02x%02x%02x" % (r, g, b, a)
        else:
            raise ValueError("Invalid color")

        self.color = color
        self.last_user_selected_color = color

    def update_color(self):
        if self.color is None or not hasattr(self.color, "lstrip"):
            return

        preview_label_text = f"<HTML><CENTER><I><FONT SIZE=2 COLOR={self.color}>click</FONT></I></CENTER>"
        self.preview_label.config(text=preview_label_text)
        self.preview_label.config(bg=self.color)

    def get_value(self):
        if self.color is None:
            return None
        else:
            return tuple(int(x.lstrip("#")) for x in self.color.split(",")[1:])

class EditorProvider:
    def __init__(self, content_panel):
        super().__init__("Color Editor", True)
        add_work_panel(content_panel)
        add_ok_button()
        add_cancel_button()

    def ok_callback(self):
        color = last_user_selected_color
        close()

def add_work_panel(content_panel):
    pass

def add_ok_button():
    pass

def add_cancel_button():
    pass


class ColorEditorPanel:
    def __init__(self, parent=None):
        self.parent = parent
        if not hasattr(color_chooser, "get_selection_model"):
            color_chooser = GhidraColorChooser()
        self.add(color_chooser)

    def get(self):
        return last_user_selected_color

def close():
    pass


class GhidraColorChooser:
    def __init__(self):
        super().__init__()
        if not hasattr(self, "get_selection_model"):
            raise ValueError("GhidraColorChooser must have a selection model")

    def set_color(self, color):
        self.color = color

last_user_selected_color = None
