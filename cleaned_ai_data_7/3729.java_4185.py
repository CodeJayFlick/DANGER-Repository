import tkinter as tk
from tkinter import ttk
from threading import Thread

class DataTypesTreeCellEditor:
    def __init__(self, treeview, renderer):
        self.tree = treeview
        self.renderer = renderer
        self.plugin = None
        self.last_edited_node = None

    def get_tree_cell_editor_component(self, value, selected, expanded, leaf, row):
        if isinstance(value, GTreeNode) and value.has_custom_editor():
            Thread(target=self.edit, args=(value,)).start()
            return self.renderer.get_tree_cell_renderer_component(
                self.tree,
                value,
                selected,
                expanded,
                leaf,
                row
            )
        else:
            self.last_edited_node = value.parent
            return super().get_tree_cell_editor_component(self.tree, value, selected, expanded, leaf, row)

    def edit(self, node):
        if isinstance(node, GTreeNode) and node.is_modifiable():
            dt = node.data_type
            self.plugin.get_editor_manager().edit(dt)
