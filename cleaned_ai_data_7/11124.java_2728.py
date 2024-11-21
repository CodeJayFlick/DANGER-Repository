class CheckoutsDialog:
    def __init__(self, tool, user, domain_file, checkouts):
        self.panel = None  # Initialize panel as None
        super().__init__("View Checkouts for " + str(domain_file), False)
        help_location = HelpLocation(GenericHelpTopics.REPOSITORY, "View_Check_Outs")
        set_help_location(help_location)  # Set the help location

    def create_actions(self):
        self.panel.create_actions(self)

    def dismiss_callback(self):
        close()
        if self.panel is not None:
            self.panel.dispose()

    def project_closed(self, project):
        self.dismiss_callback()

    def project_opened(self, project):
        pass  # Don't care

class CheckoutsActionContext:
    def __init__(self, selected_rows):
        self.selected_rows = selected_rows
