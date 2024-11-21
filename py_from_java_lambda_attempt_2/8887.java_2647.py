Here is a translation of the Java code into equivalent Python:

```Python
class CreateAndApplyManualMatchFromToolsAction:
    def __init__(self, plugin):
        super().__init__(plugin, "Create And Apply Manual Match From Tool")
        self.menu_group = "1"  # first group in the popup
        self.popup_menu_data = MenuData(
            ["{}: {}".format(VTPlugin.MATCH_POPUP_MENU_NAME, "Create And Apply Manual Match"), CreateManualMatchAndAcceptAction.ICON],
            self.menu_group)
        set_help_location(HelpLocation("VersionTrackingPlugin", 
                                        "Create_And_Apply_Manual_Match_From_Subtools"))

    def get_task(self, controller, source_function, destination_function):
        return CreateAndAcceptApplyManualMatchTask(controller, source_function, 
                                                    destination_function, True)


class MenuData:
    def __init__(self, menu_items, group):
        self.menu_items = menu_items
        self.group = group


class HelpLocation:
    def __init__(self, plugin_name, help_location):
        self.plugin_name = plugin_name
        self.help_location = help_location

```

Please note that this is a translation and not direct conversion. Python does not support some of the Java features like `package`, `import` statements or certain types (like `Function`). Also, Python's class structure is different from Java's.