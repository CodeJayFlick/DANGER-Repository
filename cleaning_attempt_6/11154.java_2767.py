class ProjectInfoDialog:
    def __init__(self, plugin):
        self.plugin = plugin
        self.project = plugin.get_active_project()
        self.repository = self.project.get_repository()

    def update_connection_status(self):
        if self.repository.is_connected():
            connection_button.set_icon(FrontEndPlugin.CONNECTED_ICON)
        else:
            connection_button.set_icon(FrontEndPlugin.DISCONNECTED_ICON)

        connection_button.set_content_area_filled(False)
        connection_button.set_selected(True)
        connection_button.set_border(BevelBorder.LOWERED)

    def build_main_panel(self):
        main_panel = JPanel(VerticalLayout())
        main_panel.setBorder(BorderFactory.createEmptyBorder(10, 5, 10, 5))
        main_panel.add(build_info_panel())
        main_panel.add(build_repository_info_panel())
        main_panel.add(build_button_panel())

        return main_panel

    def build_info_panel(self):
        info_panel = JPanel(PairLayout(5, 10))

        dir_label = GLabel("Directory Location:", SwingConstants.RIGHT)
        info_panel.add(dir_label)

        project_dir_label = GDLabel(str(self.project.get_project_locator().get_project_dir()))
        info_panel.add(project_dir_label)

        return info_panel

    def build_repository_info_panel(self):
        outer_panel = JPanel(BorderLayout())

        panel = JPanel(PairLayout(5, 10))

        server_name_label = GLabel("Server Name:", SwingConstants.RIGHT)
        panel.add(server_name_label)

        server_label = GDLabel(str(self.repository.get_server_info().get_server_name()))
        panel.add(server_label)

        port_number_label = GLabel("Port Number:", SwingConstants.RIGHT)
        panel.add(port_number_label)

        port_label = GDLabel(str(self.repository.get_server_info().get_port_number()))
        panel.add(port_label)

        repository_name_label = GLabel("Repository Name:", SwingConstants.RIGHT)
        panel.add(repository_name_label)

        rep_name_label = GDLabel(str(self.repository.get_name()))
        panel.add(rep_name_label)

        connect_button = JButton(FrontEndPlugin.CONNECTED_ICON if self.repository.is_connected() else FrontEndPlugin.DISCONNECTED_ICON)
        connect_button.addActionListener(lambda e: self.connect())

        user_access_level_label = GLabel("User Access Level:", SwingConstants.RIGHT)
        panel.add(user_access_level_label)

        user_access_level = GDLabel(get_access_string(self.repository.get_user()))
        panel.add(user_access_level)

        outer_panel.add(panel, BorderLayout.CENTER)

        return outer_panel

    def build_button_panel(self):
        button_panel = JPanel(FlowLayout())

        change_convert_button = JButton("Change Shared Project Info..." if self.repository else "Convert to Shared...")
        change_convert_button.addActionListener(lambda e: self.update_shared_project_info() if self.repository else self.convert_to_shared())
        help_service.register_help(change_convert_button, HelpLocation(GenericHelpTopics.FRONT_END, "View_Project_Info" if self.repository else "Convert_to_Shared"))

        convert_storage_button = None
        fs_class = self.project.get_project_data().get_local_storage_class()
        if IndexedV1LocalFileSystem.class == fs_class:
            convert_storage_button_label = "Upgrade Project Storage Index..."
        elif MangledLocalFileSystem.class == fs_class:
            convert_storage_button_label = "Convert Project Storage to Indexed..."

        if convert_storage_button_label is not None:
            convert_storage_button = JButton(convert_storage_button_label)
            convert_storage_button.addActionListener(lambda e: self.convert_to_indexed_filesystem())
            help_service.register_help(change_convert_button, HelpLocation(GenericHelpTopics.FRONT_END, "Convert_Project_Storage"))

        button_panel.add(change_convert_button)

        if convert_storage_button is not None:
            button_panel.add(convert_storage_button)

        return button_panel

    def update_shared_project_info(self):
        # Code to be implemented
        pass

    def convert_to_shared(self):
        # Code to be implemented
        pass

    def get_access_string(self, user):
        if user is None:
            return ""
        elif user.is_admin():
            return "Administrator"
        elif user.is_read_only():
            return "Read Only"
        else:
            return "Read/Write"

    def convert_to_indexed_filesystem(self):
        # Code to be implemented
        pass

class ConvertProjectTask(Task):
    def __init__(self, repository):
        super().__init__("Convert Project", True, False, True)
        self.repository = repository

    def run(self, monitor):
        try:
            project.get_project_data().convert_project_to_shared(self.repository, monitor)
            status = True
        except IOException as e:
            msg = str(e) if not isinstance(e, ConvertFileSystemException) else "Failed to convert project storage: " + str(e)
            Msg.show_error(self, get_component(), "Failed to Convert Project", msg)

    def is_status(self):
        return self.status

class UpdateInfoTask(Task):
    def __init__(self, repository):
        super().__init__("Update Shared Project Info", True, False, True)
        self.repository = repository

    def run(self, monitor):
        try:
            project.get_project_data().update_repository_info(self.repository, monitor)
            status = True
        except IOException as e:
            msg = str(e) if not isinstance(e, CancelledException) else "Conversion to shared project failed: " + str(e)
            Msg.show_error(self, get_component(), "Failed to Update Shared Project Info", msg)

    def is_status(self):
        return self.status

class ConvertProjectStorageTask(Task):
    def __init__(self, project_locator):
        super().__init__("Convert Project Storage", False, False, True)
        self.project_locator = project_locator

    def run(self, monitor):
        try:
            convert_file_system.convert_project(monitor)
            status = True
        except ConvertFileSystemException as e:
            Msg.show_error(self, get_component(), "Failed to Convert Project Storage", str(e))

    def is_status(self):
        return self.status
