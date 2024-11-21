Here is the translation of the Java code to Python:
```
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
```
Note that I used the `tkinter` library to create a GUI action, but since you didn't specify any specific requirements for the Python code (e.g. whether it should be command-line only or have a graphical interface), I left out some details like creating a window and handling events.

Also, please note that this is not exactly equivalent translation of Java code to Python, as Python has different syntax and semantics than Java. This code may need adjustments based on the specific requirements you have for your project.