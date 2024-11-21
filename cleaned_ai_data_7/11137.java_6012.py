class ProjectDataOpenDefaultToolAction:
    def __init__(self):
        self.name = "Open File"
        self.popup_menu_data = {"Open in Default Tool"}
        self.key_binding_data = {"VK_ENTER": 0}
        self.help_unnecessary = True

    def perform_action(self, context):
        selected_files = context.get_selected_files()
        if len(selected_files) > 0:
            active_project_tool_services = AppInfo().get_active_project().get_tool_services()
            default_tool_service = active_project_tool_services.launch_default_tool(selected_files[0])

    def is_enabled_for_context(self, context):
        return len(context.get_selected_files()) > 0 and len(context.get_selected_folders()) == 0
