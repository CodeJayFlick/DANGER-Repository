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
