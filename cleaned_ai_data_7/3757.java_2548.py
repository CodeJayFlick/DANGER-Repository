import tkinter as tk
from tkinter import filedialog, messagebox
from typing import List

class DataTypeChooserDialog:
    def __init__(self):
        self.tree = None
        self.selected_data_type = None
        self.message_label = None
        self.is_filter_editable = False

    def show_prepopulated_dialog(self, tool: tk.Tk, data_type_text: str) -> None:
        if self.tree is not None and self.tree.get() != "":
            return
        
        if data_type_text == "":
            raise ValueError("Cannot pre-populate the data type chooser dialog with blank filter text")
        
        self.tree.set_filter_text(data_type_text)
        self.is_filter_editable = False
        self.install_exact_match_filter()
        
        self.set_first_node_selected()
        tool.show()

    def set_filter_text(self, filter_text: str) -> None:
        if self.tree is not None and isinstance(self.tree, Tree):
            self.tree.set_filter_text(filter_text)

    def set_first_node_selected(self) -> None:
        if self.tree is not None and isinstance(self.tree, Tree):
            root = self.tree.get_view_root()
            dt_nodes = []
            get_data_type_nodes(root, dt_nodes)
            
            if len(dt_nodes) > 0:
                self.tree.set_selected_node(dt_nodes[0])

    def set_selected_path(self, selected_path: str) -> None:
        if self.tree is not None and isinstance(self.tree, Tree):
            self.tree.set_selected_node_by_path_name(selected_path)

    def set_filter_field_editable(self, editable: bool) -> None:
        self.is_filter_editable = editable
        if self.tree is not None and isinstance(self.tree, Tree):
            self.tree.set_filter_field_enabled(editable)

    def get_tree_filter_provider(self) -> object:
        return self.tree.get_filter_provider()

    def set_tree_filter_provider(self, provider: object) -> None:
        if self.tree is not None and isinstance(self.tree, Tree):
            self.tree.set_filter_provider(provider)

    @property
    def selected_data_type(self) -> str:
        return self.selected_data_type

class Tree:
    def __init__(self, root: tk.Tk):
        pass
    
    def set_filter_text(self, filter_text: str) -> None:
        pass

    def get_view_root(self) -> object:
        pass

    def set_selected_node_by_path_name(self, selected_path: str) -> None:
        pass

class GTreeNode:
    def __init__(self):
        pass
    
    @property
    def children(self) -> List['GTreeNode']:
        return []

def get_data_type_nodes(node: 'GTreeNode', dt_nodes: List['GTreeNode']) -> None:
    if isinstance(node, DataTypeNode):
        dt_nodes.append(node)
        return

    for child in node.children:
        get_data_type_nodes(child, dt_nodes)

class DataTypeNode(GTreeNode):
    def __init__(self, data_type: str):
        self.data_type = data_type
    
    @property
    def children(self) -> List['GTreeNode']:
        # implement this method to return the list of child nodes for a given node
        pass

def main():
    root = tk.Tk()
    
    dialog = DataTypeChooserDialog()

    tool = None  # replace with your actual Tkinter window
    
    data_type_text = "your_data_type_here"  # replace with your desired filter text
    
    try:
        dialog.show_prepopulated_dialog(tool, data_type_text)
    except ValueError as e:
        messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    main()
