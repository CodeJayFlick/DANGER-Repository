Here is the translation of the given Java code into Python:

```Python
import tkinter as tk
from PIL import ImageTk, Image

class ProjectDataCutAction:
    icon = None

    def __init__(self):
        self.icon = Image.open("images/edit-cut22.png")
        super().__init__("Cut", "owner")

    def set_popup_menu_data(self, menu_data):
        return new MenuData(["Cut"], self.icon, "group")

    def set_key_binding_data(self, key_binding_data):
        return KeyBindingData('X', tk.CONTROL)

    def mark_help_unnecessary(self):
        pass

class FrontEndProjectTreeContext:
    def __init__(self):
        super().__init__()

    def get_selection_paths(self):
        # This method should be implemented
        pass

    def is_in_active_project(self):
        return True  # Assuming the project is active by default

    def contains_root_folder(self):
        return False  # Assuming there's no root folder selected


class DataTreeClipboardUtils:
    @staticmethod
    def set_clipboard_contents(tree, paths):
        # This method should be implemented
        pass

    @staticmethod
    def mark_nodes_cut(paths):
        for path in paths:
            node = tree.get_node(path)
            if isinstance(node, Cuttable):
                node.set_is_cut(True)


class GTreeNode:
    def __init__(self):
        super().__init__()

    def get_last_component(self):
        # This method should be implemented
        pass


class Cuttable(GTreeNode):
    is_cut = False

    def set_is_cut(self, value):
        self.is_cut = value


# Usage example:

action = ProjectDataCutAction()
context = FrontEndProjectTreeContext()

paths = context.get_selection_paths()  # This method should be implemented
if action.isEnabledForContext(context) and paths:
    DataTreeClipboardUtils.set_clipboard_contents(tree, paths)
    DataTreeClipboardUtils.mark_nodes_cut(paths)

```

Please note that this translation is not a direct conversion from Java to Python. The code has been modified to fit the structure of Python classes and methods. Some parts may need further modification based on your specific requirements.

The `FrontEndProjectTreeContext` class's `get_selection_paths`, `is_in_active_project`, and `contains_root_folder` methods are not implemented in this translation, as they seem to be dependent on a GUI framework like Swing or Tkinter.