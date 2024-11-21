class ResetFormatAction:
    def __init__(self, owner, panel):
        self.panel = panel
        super().__init__("Reset Format", owner, False)

        menu_data = {"Reset Format": None}
        self.set_popup_menu_data(menu_data)
        self.enabled = True

        help_location = HelpLocation(HelpTopics.CODE_BROWSER, "Reset Format")
        self.set_help_location(help_location)

    def is_enabled_for_context(self, context):
        return isinstance(context.get_context_object(), FieldHeaderLocation)

    def action_performed(self, context):
        user_choice = OptionDialog.show_option_dialog(
            panel,
            "Reset Format?",
            f"There is no undo for this action.\n" + 
            "Are you sure you want to reset the current format? ",
            "Continue",
            OptionDialog.WARNING_MESSAGE
        )
        
        if user_choice == OptionDialog.CANCEL_OPTION:
            return

        self.panel.set_tab_lock(True)
        self.panel.reset_format()
        self.panel.get_header_tab().update()

