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
