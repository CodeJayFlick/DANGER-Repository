class DebugDecompilerAction:
    def __init__(self, controller):
        self.controller = controller
        super().__init__("Debug Function Decompilation")
        help_location = HelpLocation(HelpTopics.DECOMPILER, "ToolBarDebug")
        set_help_location(help_location)
        menu_bar_data = MenuData(["Debug Function Decompilation"], "xDebug")
        set_menu_bar_data(menu_bar_data)

    def is_enabled_for_decompiler_context(self, context):
        return context.get_function() is not None

    def decompiler_action_performed(self, context):
        parent_component = context.get_deompiler_panel()
        file_chooser = GhidraFileChooser(parent_component)
        file_chooser.set_title("Please Choose Output File")
        file_chooser.set_file_filter(ExtensionFileFilter(["xml"], "XML Files"))
        selected_file = file_chooser.get_selected_file()
        if not selected_file:
            return
        if selected_file.exists():
            if OptionDialog.show_yes_no_dialog(parent_component, "Overwrite Existing File?", 
                "Do you want to overwrite the existing file?") == OptionDialog.OPTION_TWO:
                return
        self.controller.set_status_message(f"Dumping debug info to {selected_file.get_absolute_path()}")
        self.controller.refresh_display(self.controller.get_program(), self.controller.get_location(), selected_file)
