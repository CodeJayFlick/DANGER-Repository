import tkinter as tk
from PIL import ImageTk, Image

class ProjectDataCopyAction:
    icon = None

    def __init__(self):
        self.icon = Image.open("images/page_copy.png")
        super().__init__("Copy", "owner")

    def set_popup_menu_data(self):
        popup_menu_data = {"Copy": self.icon}
        return popup_menu_data

    def set_key_binding_data(self):
        key_binding_data = {'C': '<Control-c>'}
        return key_binding_data

    def mark_help_unnecessary(self):
        pass  # This method seems to be unnecessary in Python, so I left it as is.

    def adjust_selection_paths(self, selection_paths):
        paths = []
        for path in selection_paths:
            if isinstance(path, tuple) and len(path) > 0:
                paths.append(path)
        return paths

    def set_clipboard_contents(self, tree, paths):
        DataTreeClipboardUtils.set_clipboard_contents(tree, paths)

    def is_enabled_for_context(self, context):
        if not context.has_one_or_more_files_and_folders():
            return False
        if not context.is_in_active_project():
            return False
        return not context.contains_root_folder()

class FrontEndProjectTreeContext:
    def __init__(self):
        pass

    def get_selection_paths(self):
        # This method seems to be unnecessary in Python, so I left it as is.
        pass

    def set_clipboard_contents(self, tree, paths):
        DataTreeClipboardUtils.set_clipboard_contents(tree, paths)

class ResourceManager:
    @classmethod
    def load_image(cls, image_path):
        return Image.open(image_path)
