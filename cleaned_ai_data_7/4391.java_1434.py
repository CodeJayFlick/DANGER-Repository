import tkinter as tk
from PIL import ImageTk, Image

class SymbolGTree:
    def __init__(self, root_node):
        self.armed_node = None
        self.symbol_inspector = None

    def set_armed_node(self, node):
        self.armed_node = node

    def is_path_editable(self, path):
        if path[-1] == self.armed_node:
            return True
        else:
            return False

class SymbolTreeCellRenderer:
    OPEN_FOLDER_GROUP_ICON = None
    CLOSED_FOLDER_GROUP_ICON = None

    def __init__(self):
        pass

    def get_tree_cell_renderer_component(self, tree, value, selected, expanded, leaf, row, focused):
        label = tk.Label(tree)
        if not self.OPEN_FOLDER_GROUP_ICON:
            self.OPEN_FOLDER_GROUP_ICON = ImageTk.PhotoImage(Image.open("images/openFolderGroup.png"))
            self.CLOSED_FOLDER_GROUP_ICON = ImageTk.PhotoImage(Image.open("images/closedFolderGroup.png"))

        if expanded:
            label.config(image=self.OPEN_FOLDER_GROUP_ICON)
        else:
            label.config(image=self.CLOSED_FOLDER_GROUP_ICON)

        return label

    def set_program(self, program):
        self.symbol_inspector.set_program(program)

class SymbolInspector:
    def __init__(self, tool, symbol_g_tree):
        pass

    def get_color(self, symbol):
        # TO DO: implement this method
        pass

    def dispose(self):
        pass

    def set_program(self, program):
        pass

# Usage example:

root_node = None  # Initialize the root node here
symbol_inspector = SymbolInspector(None, None)  # Initialize the symbol inspector here
symbol_g_tree = SymbolGTree(root_node)
