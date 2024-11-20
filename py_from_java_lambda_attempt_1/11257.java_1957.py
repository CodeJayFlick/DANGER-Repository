Here is a translation of the provided Java code into equivalent Python:

```Python
class StandAlonePluginTool:
    def __init__(self, app: 'GenericStandAloneApplication', name: str, has_status: bool):
        self.plugin_class_manager = None
        self.configure_tool_action = None
        self.app = app
        self.name = name

    @property
    def plugin_class_manager(self) -> 'PluginClassManager':
        if not self._plugin_class_manager:
            self._plugin_class_manager = PluginClassManager(Plugin, None)
        return self._plugin_class_manager

    def add_exit_action(self):
        exit_action = DockingAction("Exit", "TOOL_OWNER")
        exit_action.actionPerformed = lambda context: self.app.exit()
        exit_action.help_location = HelpLocation("FRONT_END_HELP_TOPIC", exit_action.name)

        if Platform.CURRENT_PLATFORM.OPERATING_SYSTEM != OperatingSystem.MAC_OS_X:
            # Mac Handles this action 'special'
            exit_action.key_binding_data = KeyBindingData(KeyEvent.VK_Q, InputEvent.CTRL_DOWN_MASK)
        
        exit_action.enabled = True
        self.add_action(exit_action)

    def add_export_tool_action(self):
        super().add_export_tool_action()

    def add_save_tool_action(self):
        super().add_save_tool_action()

    def add_manage_plugins_action(self):
        configure_tool_action = DockingAction("Configure Tool", "TOOL_OWNER")
        configure_tool_action.actionPerformed = lambda context: self.show_config(False, False)
        
        configure_tool_action.menu_bar_data = MenuData(["MENU_FILE", f"Configure..."], None, "PrintPost_PreTool")

        configure_tool_action.enabled = True
        self.add_action(configure_tool_action)

    def show_config(self, *args):
        pass

class PluginClassManager:
    def __init__(self, plugin_class: 'Plugin', parent=None):
        self.plugin_class = plugin_class
        self.parent = parent

# Other classes and functions will be needed to translate the provided code into Python.
```

Please note that this translation is not a direct conversion from Java to Python. The structure of your original code has been maintained, but some changes have been made to accommodate Python's syntax and conventions.

Here are some key differences:

1.  Inheritance: Python does not support inheritance in the same way as Java. Instead, you can use composition or multiple inheritance.
2.  Method overriding: Python uses a different approach for method overriding than Java. You don't need to explicitly declare methods with `@Override`.
3.  Properties: Python has no direct equivalent of properties like Java's getter and setter methods. However, the provided code demonstrates how you can achieve similar functionality using Python's property decorator.
4.  Lambda functions: The original code uses lambda expressions for event handling in Java. In Python, these are replaced with regular function definitions or lambda functions.

The translation also assumes that some classes (like `GenericStandAloneApplication`, `PluginClassManager`, and others) have been defined elsewhere in the program.