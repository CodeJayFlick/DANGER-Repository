class NextColorRangeAction:
    def __init__(self, plugin: 'ColorizingPlugin', tool: object, nav_options: dict):
        super().__init__()
        self.plugin = plugin
        self.set_menu_bar_data(["Navigation", "Next Color Range"], None, "NAVIGATION", 0)
        self.setDescription("Go to next color range")
        self.set_help_location("CodeBrowserPlugin", "Color_Navigation")

    def get_selection(self, context: dict) -> object:
        return ProgramSelection(self.plugin.getColorizingService().getAllBackgroundColorAddresses())

    def remove(self):
        self.set_tool_bar_data(None)


class ColorizingPlugin:
    NAVIGATION_TOOLBAR_SUBGROUP = 0

    def __init__(self):
        pass


class NavigationOptions(dict):
    pass


class PluginTool(object):
    MENU_NAVIGATION = "Navigation"
    NO_MNEMONIC = 0
