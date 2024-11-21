import tkinter as tk
from tkinter import ttk

class ControlPanel:
    def __init__(self, plugin, dialog):
        self.root = tk.Tk()
        self.root.title("Control Panel")
        self.root.geometry("300x100")

        self.range_widget = SelectionScopeWidget(plugin, "Selection Scope", dialog)
        self.direction_widget = SearchDirectionWidget("Search Direction", dialog)

        grid_frame = ttk.Frame(self.root)
        grid_frame.pack(fill=tk.BOTH, expand=True)

        range_grid = tk.Grid()
        direction_grid = tk.Grid()

        range_grid.grid(row=0, column=0, sticky="nsew")
        self.range_widget.pack_in(grid_frame, side=tk.LEFT, fill=tk.X)

        direction_grid.grid(row=1, column=0, sticky="nsew")
        self.direction_widget.pack_in(grid_frame, side=tk.LEFT, fill=tk.X)

    def get_range_widget(self):
        return self.range_widget

    def get_direction_widget(self):
        return self.direction_widget


class SelectionScopeWidget:
    def __init__(self, plugin, label, dialog):
        self.plugin = plugin
        self.label = tk.Label(text=label)
        self.dialog = dialog

    def pack_in(self, parent, side=tk.TOP, fill=None):
        if fill is None:
            fill = tk.X
        self.label.pack(side=side, fill=fill)


class SearchDirectionWidget:
    def __init__(self, label, dialog):
        self.label = tk.Label(text=label)
        self.dialog = dialog

    def pack_in(self, parent, side=tk.TOP, fill=None):
        if fill is None:
            fill = tk.X
        self.label.pack(side=side, fill=fill)


if __name__ == "__main__":
    plugin = "Ghidra"
    dialog = "Instruction Search Dialog"

    control_panel = ControlPanel(plugin, dialog)

    # Show the GUI
    control_panel.root.mainloop()
