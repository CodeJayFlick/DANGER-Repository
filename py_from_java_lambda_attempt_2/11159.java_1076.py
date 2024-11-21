Here is a translation of the Java code into equivalent Python:

```Python
class RunningToolsPanel:
    def __init__(self, plugin, ws):
        self.plugin = plugin
        self.running_toolbar = None
        self.running_tools = {}

        if ws is not None:
            tools = ws.get_tools()
            for tool in tools:
                self.add_tool(tool)

    @property
    def running_toolbar(self):
        if self._running_toolbar is None:
            self._running_toolbar = JToolBar(JToolbar.HORIZONTAL)
            self._running_toolbar.set_floatable(False)
            self._running_toolbar.setBorderPainted(False)
            DockingUtils.set_transparent(self._running_toolbar)
        return self._running_toolbar

    @property
    def running_tools(self):
        if not hasattr(self, '_running_tools'):
            self._running_tools = {}
        return self._running_tools

    def add_tool(self, tool):
        button = ToolButton(self.plugin, tool, tool.get_template(True))
        self.running_toolbar.add(button)
        self.running_tools[tool] = button
        self.running_toolbar.invalidate()
        self.validate()
        self.repaint()

    def remove_tool(self, tool):
        if tool in self.running_tools:
            button = self.running_tools.pop(tool)
            self.running_toolbar.remove(button)
            button.dispose()
            self.running_toolbar.invalidate()
            self.validate()
            self.repaint()

    def update_tool_button(self, tool, template, icon):
        if tool in self.running_tools:
            button = self.running_tools[tool]
            button.set_template(template, icon)
            self.validate()
            self.repaint()


class ToolButton:
    pass


class JToolBar:
    HORIZONTAL = 0
    VERTICAL = 1

    def __init__(self, orientation):
        pass

    @property
    def is_floatable(self):
        return False

    @is_floatable.setter
    def is_floatable(self, value):
        self._is_floatable = value

    @property
    def border_painted(self):
        return False

    @border_painted.setter
    def border_painted(self, value):
        self._border_painted = value


class DockingUtils:
    @staticmethod
    def set_transparent(toolbar):
        pass


# This is a placeholder for the Java classes that are not directly translatable to Python.
```

Please note that this translation does not include all of the original code. Some parts, such as `FrontEndPlugin`, `Workspace`, and `ToolTemplate` were left out because they do not have direct equivalents in Python.