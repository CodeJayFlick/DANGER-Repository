import tkinter as tk
from PIL import ImageTk

class DecompilerNestedLayoutProvider:
    ICON = None  # Initialize icon variable
    LAYOUT_NAME = "Nested Code Layout"

    def __init__(self):
        self.ICON = ImageTk.PhotoImage(file="images/function_graph_code_flow.png")

    def get_fg_layout(self, graph: dict, monitor: str) -> dict:
        layout = {"name": self.LAYOUT_NAME}
        return layout

    def create_layout_options(self, options: dict) -> dict:
        layout_options = {}
        # register options with the framework
        return layout_options

    def get_layout_name(self) -> str:
        return self.LAYOUT_NAME

    def get_action_icon(self) -> tk.PhotoImage:
        return self.ICON

    def get_priority_level(self) -> int:
        return 200


# Example usage:
provider = DecompilerNestedLayoutProvider()
graph = {"some_graph_data": "..."}
monitor = "..."
layout = provider.get_fg_layout(graph, monitor)
print(layout)

options = {}
layout_options = provider.create_layout_options(options)
print(layout_options)

name = provider.get_layout_name()
icon = provider.get_action_icon()

priority_level = provider.get_priority_level()
