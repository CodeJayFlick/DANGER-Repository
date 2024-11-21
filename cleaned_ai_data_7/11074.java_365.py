class EditActionManager:
    def __init__(self, plugin):
        self.plugin = plugin
        self.tool = plugin.get_tool()
        self.create_actions()

    def create_actions(self):
        # window.addSeparator(Ghidra.MENU_FILE);

        self.edit_plugin_path_action = DockingAction("Edit Plugin Path", self.plugin.name)
        self.edit_plugin_path_action.actionPerformed = lambda context: self.edit_plugin_path()
        self.edit_plugin_path_action.enabled = True
        self.edit_plugin_path_action.menu_bar_data = MenuData([ToolConstants.MENU_EDIT, "Plugin Path...", "GEdit"])

        self.edit_cert_path_action = DockingAction("Set PKI Certificate", self.plugin.name)
        self.edit_cert_path_action.actionPerformed = lambda context: self.edit_cert_path()
        self.edit_cert_path_action.enabled = True
        self.edit_cert_path_action.menu_bar_data = MenuData([ToolConstants.MENU_EDIT, "Set PKI Certificate...", "PKI"])

        self.clear_cert_path_action = DockingAction("Clear PKI Certificate", self.plugin.name)
        self.clear_cert_path_action.actionPerformed = lambda context: self.clear_cert_path()
        if ApplicationKeyManagerFactory.get_key_store() is not None:
            self.clear_cert_path_action.enabled = True
        else:
            self.clear_cert_path_action.enabled = False

        self.clear_cert_path_action.menu_bar_data = MenuData([ToolConstants.MENU_EDIT, "Clear PKI Certificate...", "PKI"])
        self.clear_cert_path_action.help_location = HelpLocation("FrontEndPlugin", "Set_PKI_Certificate")
        self.tool.add_action(self.edit_cert_path_action)
        self.tool.add_action(self.clear_cert_path_action)
        self.tool.add_action(self.edit_plugin_path_action)

    def edit_plugin_path(self):
        if not hasattr(self, 'plugin_path_dialog'):
            self.plugin_path_dialog = EditPluginPathDialog()
        self.plugin_path_dialog.show(self.tool)

    def clear_cert_path(self):
        path = ApplicationKeyManagerFactory.get_key_store()
        if path is None:
            # unexpected
            self.clear_cert_path_action.enabled = False
            return

        if OptionDialog.YES_OPTION != OptionDialog.show_yes_no_dialog(self.tool.get_tool_frame(), "Clear PKI Certificate", f"Clear PKI certificate setting? ({path})"):
            return

        try:
            ApplicationKeyManagerFactory.set_key_store(None, True)
            self.clear_cert_path_action.enabled = False
        except IOException as e:
            Msg.error(self, f"Error occurred while clearing PKI certificate setting: {e.message}")

    def edit_cert_path(self):
        if not hasattr(self, 'cert_filechooser'):
            self.cert_filechooser = create_cert_filechooser()

        dir = None
        old_file = None
        path = ApplicationKeyManagerFactory.get_key_store()
        if path is not None:
            old_file = File(path)
            dir = old_file.parent
            if not old_file.file():
                old_file = None
                if not dir.directory():
                    dir = None

        if dir is None:
            dir = File(System.getProperty("user.home"))

        if old_file is not None:
            self.cert_filechooser.set_selected_file(old_file)
        else:
            self.cert_filechooser.set_current_directory(dir)

        while True:
            # display the file chooser and handle the action, Select or Create
            file = self.cert_filechooser.get_selected_file()
            if file is None:
                return  # cancelled

            try:
                ApplicationKeyManagerFactory.set_key_store(file.absolute_path(), True)
                self.clear_cert_path_action.enabled = True
                break
            except IOException as e:
                Msg.show_error(self, self.tool.get_tool_frame(), "Certificate Failure", f"Failed to initialize key manager.\n{e.message}", e)

    def create_cert_filechooser(self):
        file_chooser = GhidraFileChooser(self.tool.get_tool_frame())
        file_chooser.set_title("Select Certificate (req'd for PKI authentication only)")
        file_chooser.set_approve_button_text("Set Certificate")
        file_chooser.set_file_filter(ApplicationKeyManagerFactory.CERTIFICATE_FILE_FILTER)
        file_chooser.set_file_selection_mode(GhidraFileChooser.FILES_ONLY)
        file_chooser.set_help_location(HelpLocation(self.plugin.name, "Set_PKI_Certificate"))
        return file_chooser
