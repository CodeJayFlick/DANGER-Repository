import tkinter as tk

class OpenProjectArchiveAction:
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__("Open Project Data Type Archive", plugin.name)

# ACTIONS - auto generated
        menu_bar_data = {"menu": ["Open Project Archive..."], "submenu": None, "label": "Archive"}
        set_menu_bar_data(menu_bar_data)
        description = "Opens a project data type archive in this data type manager."
        enabled = True

    def actionPerformed(self):
        self.plugin.open_project_data_type_archive()

if __name__ == "__main__":
    pass
