class AboutProgramPlugin:
    PLUGIN_NAME = "AboutProgramPlugin"
    ACTION_NAME = "About Program"

    def __init__(self):
        pass

    def setup_actions(self):
        if isinstance(tool, FrontEndTool):
            about_action = FrontendProjectTreeAction(ACTION_NAME, PLUGIN_NAME)
            about_action.actionPerformed = lambda context: self.show_about(context.getSelectedFiles()[0], context.getSelectedFiles()[0].get_metadata())
            about_action.is_add_to_popup = lambda context: context.getFileCount() == 1 and context.getFolderCount() == 0
            about_action.setPopupMenuData(MenuData([ACTION_NAME], None, "AAA"))
            about_action.setEnabled(True)
        else:
            about_action = ProgramContextAction(ACTION_NAME, PLUGIN_NAME)
            about_action.actionPerformed = lambda context: self.show_about(context.getProgram().getDomainFile(), context.getProgram().get_metadata())
            about_action.isValid_context = lambda context: super().isValid_context(context) and isinstance(context, ProgramActionContext) and context.getProgram() is not None
            about_action.addToWindowWhen(ProgramActionContext)
            about_action.setSupportsDefaultToolContext(True)
            about_action.setMenuBarData(MenuData([ToolConstants.MENU_HELP, ACTION_NAME], None, "ZZZ"))
            about_action.setEnabled(False)

        about_action.setHelpLocation(HelpLocation(GenericHelpTopics.ABOUT, "About_Program"))
        about_action.setDescription(get_plugin_description().getDescription())
        tool.addAction(about_action)

    def show_about(self, domain_file, metadata):
        help_location = HelpLocation(GenericHelpTopics.ABOUT, "About_Program")
        AboutDomainObjectUtils.display_information(tool, domain_file, metadata, f"About {domain_file.name}", None, help_location)
