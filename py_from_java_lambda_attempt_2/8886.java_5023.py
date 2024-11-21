Here is the translation of the Java code to Python:
```
class CreateAndAcceptManualMatchFromToolsAction:
    def __init__(self, plugin):
        super().__init__(plugin, "Create And Accept Manual Match From Tool")
        self.menu_group = "1"  # first group in the popup
        menu_data = {"name": VTPlugin.MATCH_POPUP_MENU_NAME,
                     "label": "Create And Accept Manual Match",
                     "icon": CreateManualMatchAndAcceptAction.ICON,
                     "menu_group": self.menu_group}
        self.set_popup_menu_data(menu_data)
        help_location = HelpLocation("VersionTrackingPlugin", 
                                      "Create_And_Accept_Manual_Match_From_Subtools")
        self.set_help_location(help_location)

    def get_task(self, controller, source_function, destination_function):
        return CreateAndAcceptApplyManualMatchTask(controller, 
                                                    source_function, 
                                                    destination_function, 
                                                    False)
```
Note that I've used the following Python concepts:

* Classes and objects: `CreateAndAcceptManualMatchFromToolsAction` is a class with an initializer (`__init__`) method.
* Inheritance: The class inherits from `AbstractManualMatchFromToolsAction`, which is not shown in this code snippet.
* Dictionary-based configuration: I've used dictionaries to represent the menu data and help location, similar to how Java uses objects for these purposes.
* Method calls: Python methods are called using dot notation (e.g., `self.set_popup_menu_data(menu_data)`).
* Boolean values: In Python, booleans are represented as `True` or `False`, not integers like in Java.

Please note that this is a direct translation of the Java code to Python and might require some adjustments depending on your specific use case.