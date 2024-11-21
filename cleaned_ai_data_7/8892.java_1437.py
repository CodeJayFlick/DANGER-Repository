class CreateManualMatchFromToolsAction:
    NAME = "Create Manual Match From Tool"

    def __init__(self, plugin):
        super().__init__(plugin, self.NAME)
        menu_group = "1"  # first group in the popup
        set_popup_menu_data(new MenuData([VTPlugin.MATCH_POPUP_MENU_NAME, 
            "Create Manual Match"], CreateManualMatchAction.ICON, menu_group))
        help_location = HelpLocation("VersionTrackingPlugin", 
            "Create_Manual_Match_From_Subtools")
        self.set_help_location(help_location)

    def get_task(self, controller, source_function, destination_function):
        return CreateManualMatchTask(controller.get_session(), source_function, 
            destination_function)
