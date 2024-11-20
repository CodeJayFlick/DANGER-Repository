Here's a translation of the given Java code into equivalent Python:

```Python
class DummyPluginTool:
    def __init__(self):
        super().__init__(None, None, DummyToolServices(), "Dummy Tool", True, True, False)

    @property
    def plugin_class_manager(self):
        return None

class DummyToolServices:
    def close_tool(self, tool):
        pass  # System.exit(0) is not needed in Python


# Example usage of the classes:

dummy_plugin_tool = DummyPluginTool()
print(dummy_plugin_tool.plugin_class_manager)
```

This code defines two classes: `DummyPluginTool` and `DummyToolServices`. The `DummyPluginTool` class has an initializer that calls its parent's (`super().__init__`) with some dummy values. It also overrides the `get_plugin_class_manager()` method to return None.

The `DummyToolServices` class is a simple subclass of another (unnamed) class, and it provides a `close_tool()` method that does nothing when called.

In the example usage at the end, we create an instance of `DummyPluginTool`, print its `plugin_class_manager` property, which returns None.