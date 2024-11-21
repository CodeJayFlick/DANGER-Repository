import tkinter as tk

class GTreeClearSelectionTask:
    def __init__(self, tree, j_tree):
        self.tree = tree
        self.j_tree = j_tree

    def run(self):
        self.tree.after(0, lambda: self.j_tree.selection_clear())

# Example usage:
tree = tk.Tk()
j_tree = tk.treectrl.Treeview(tree)
g_task = GTreeClearSelectionTask(j_tree, None)  # Pass the tree and JTree to the task
