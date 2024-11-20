import tkinter as tk

class InProgressGTreeNode:
    ICON = None

    def __init__(self):
        pass

    def get_icon(self, expanded=False):
        return self.ICON

    def get_name(self):
        return "In Progress..."

    def get_tooltip(self):
        return "Please wait while building tree nodes."

    def is_leaf(self):
        return True

    def compare_to(self, o):
        return 0
