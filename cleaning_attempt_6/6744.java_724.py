import tkinter as tk

class ToggleEditAction:
    def __init__(self, provider):
        self.provider = provider
        self.action_name = "Enable/Disable Byteviewer Editing"
        self.plugin_name = ""
        self.toolbar_data = None
        self.key_binding_data = None
        self.description = "Enable/Disable editing of bytes in Byte Viewer panels."
        self.selected = False
        self.enabled = True

    def set_toolbar_data(self, image_path, tooltip):
        self.toolbar_data = {"image": tk.PhotoImage(file=image_path), "tooltip": tooltip}

    def set_key_binding_data(self, key_code, modifiers):
        self.key_binding_data = {"key_code": key_code, "modifiers": modifiers}

    def get_action_name(self):
        return self.action_name

    def is_selected(self):
        return self.selected

    def select(self, selected):
        self.selected = selected
        if not selected:
            self.enabled = False
        else:
            self.enabled = True

    def perform_action(self):
        if self.is_selected():
            self.provider.set_edit_mode(True)
        else:
            self.provider.set_edit_mode(False)

# Example usage:
class ByteViewerComponentProvider:
    def set_edit_mode(self, enabled):
        print(f"Setting edit mode to {enabled}")

provider = ByteViewerComponentProvider()
action = ToggleEditAction(provider)
print(action.get_action_name())  # Output: Enable/Disable Byteviewer Editing
