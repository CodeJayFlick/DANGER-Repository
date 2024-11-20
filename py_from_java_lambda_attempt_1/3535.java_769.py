Here is a translation of the Java code into equivalent Python code:

```Python
class PreviousColorRangeAction:
    def __init__(self, plugin: 'ColorizingPlugin', tool: 'PluginTool', nav_options: 'NavigationOptions'):
        super().__init__()
        self.plugin = plugin
        self.set_name("Previous Color Range")
        self.set_description("Go to previous color range")

    @property
    def menu_bar_data(self):
        return {
            "menu": ["NAVIGATION", "Previous Color Range"],
            "parent_menu": None,
            "category": "NAVIGATION",
            "mnemonic": 0,
            "subgroup": self.plugin.NAVIGATION_TOOLBAR_SUBGROUP
        }

    @property
    def help_location(self):
        return {
            "topic": "CodeBrowserPlugin",
            "section": "Color_Navigation"
        }

    def get_selection(self, context: 'ProgramLocationActionContext'):
        return ProgramSelection(self.plugin.get_colorizing_service().get_all_background_color_addresses())

    def remove(self):
        self.set_tool_bar_data(None)


class ColorizingPlugin:
    NAVIGATION_TOOLBAR_SUBGROUP = None

    def __init__(self):
        pass


class NavigationOptions:
    pass


class PluginTool:
    pass


class ProgramLocationActionContext:
    pass


class ProgramSelection:
    def __init__(self, addresses: list):
        self.addresses = addresses
```

Please note that this translation is not a direct equivalent of the Java code. Python does not support some features like static methods or inner classes directly.