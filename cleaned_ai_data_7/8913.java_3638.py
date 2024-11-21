class ResetToolAction:
    def __init__(self, controller, tool_manager):
        self.controller = controller
        self.tool_manager = tool_manager
        super().__init__("Reset Sub Tools", "VTPlugin")
        menu_path = [f"{ToolConstants.MENU_EDIT}/Reset Source and Destination Tools"]
        set_menu_bar_data(MenuData(menu_path))
        description = "Resets source and destination program tools back to default configurations."
        self.set_description(description)
        help_location = HelpLocation("VersionTrackingPlugin", "Reset_Tools")
        self.set_help_location(help_location)

    def actionPerformed(self, context):
        session = self.controller.get_session()
        if session is not None:
            result = OptionDialog.show_yes_no_dialog(
                self.controller.get_tool().get_tool_frame(),
                "Restart Session?",
                f"This action needs to close and reopen the {session}.\nDo you want to continue?"
            )
            if result == OptionDialog.NO_OPTION:
                return
            if isinstance(session, VTSessionDB):
                vt_session_file = session.get_domain_file()
            if not self.controller.close_version_tracking_session():
                return  # user cancelled during save dialog
        self.tool_manager.reset_tools()

        if vt_session_file is not None:
            self.controller.open_version_tracking_session(vt_session_file)
