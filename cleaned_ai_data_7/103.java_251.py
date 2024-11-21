import tkinter as tk
from PIL import ImageTk, Image

class ZoomOutAction:
    def __init__(self, provider):
        self.provider = provider
        self.icon = Image.open("images/zoom_out.png").convert('RGB')
        self.icon = ImageTk.PhotoImage(self.icon)
        
        super().__init__("Zoom Out (Addrs)", provider.name)
        self.set_enabled(True)

        tool_bar_data = {"icon": self.icon, "tooltip": "aoverview"}
        self.set_tool_bar_data(tool_bar_data)

        self.description = "Zoom Out (A)"
        self.help_location = ("DebuggerMemviewPlugin", "zoom")

    def is_enabled_for_context(self):
        return True

    def action_performed(self):
        self.provider.change_zoom_a(-1)
        self.provider.refresh()
