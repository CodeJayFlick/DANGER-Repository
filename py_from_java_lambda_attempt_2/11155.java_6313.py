Here is a translation of the Java code into equivalent Python:

```Python
import tkinter as tk
from collections import defaultdict

class ProjectToolBar:
    def __init__(self):
        self.tool_button_map = {}
        self.plugin = None
        self.tool = None

    def set_plugin(self, plugin):
        self.plugin = plugin
        self.tool = plugin.get_tool()
        self.set_active_project(plugin.get_active_project())

    def set_active_project(self, project):
        if not hasattr(self, 'tool_button_map'):
            return
        self.clear()

        if project is None:
            return

        self.populate_toolbar()

    def clear(self):
        for button in list(self.tool_button_map.values()):
            button.destroy()
        self.tool_button_map = defaultdict(dict)

    def populate_toolbar(self):
        self.remove_all()
        self.tool_button_map = {}
        tool_chest = self.plugin.get_active_project().get_local_tool_chest()
        templates = [template for template in tool_chest.get_tool_templates()]
        for template in templates:
            self.add_config(template)
        self.invalidate()

    def add_config(self, tool_template):
        button = ToolButton(self.plugin, tool_template)
        self.add(button)
        self.tool_button_map[tool_template.name] = button

    def get_tool_button_for_tool_config(self, tool_template):
        return self.tool_button_map.get(tool_template.name)

class ToolButton:
    def __init__(self, plugin, tool_template):
        pass  # Implement the constructor for this class
```

Please note that Python does not have direct equivalent of Java's Swing and AWT libraries. This code is a translation in terms of logic but may require additional modifications to work with actual GUI components.

Also, some methods like `setBorder`, `removeAll` are not directly available in tkinter (Python's standard library for creating simple graphical user interfaces). You would need to implement these manually or use third-party libraries.