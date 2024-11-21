Here is a translation of the Java code into equivalent Python:

```Python
class ServerInfoPanel:
    def __init__(self):
        self.server_info_component = None
        self.panel_manager = None
        self.help_location = None

    def get_title(self):
        return "Specify Server Information"

    def get_help_location(self):
        if self.help_location is not None:
            return self.help_location
        else:
            return HelpLocation("ServerInfo")

    def initialize(self, panel_manager):
        self.panel_manager = panel_manager
        self.server_info_component.status_listener = self.panel_manager.get_wizard_manager()

    def isValidInformation(self):
        return self.server_info_component.is_valid_information

    @property
    def server_name(self):
        return self.server_info_component.server_name

    @property
    def port_number(self):
        return self.server_info_component.port_number

    def set_server_info(self, info):
        self.server_info_component.set_server_info(info)

    def set_help_location(self, help_loc):
        self.help_location = help_loc


class HelpLocation:
    def __init__(self, topic):
        self.topic = topic
```

Please note that Python does not have direct equivalent of Java's Swing library. The above code is a simplified version and might need to be modified based on the actual requirements.

Also, this translation assumes that `ServerInfoComponent`, `PanelManager` and `WizardManager` are classes defined elsewhere in your program or imported from other modules.