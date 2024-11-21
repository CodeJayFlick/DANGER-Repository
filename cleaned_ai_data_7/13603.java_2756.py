class ConfigureGradleWizardPage:
    def __init__(self, project_page):
        self.project_page = project_page
        super().__init__("Configure Gradle")
        self.setTitle("Configure Gradle")
        self.setDescription("Configure Gradle.")

    def create_control(self, parent):
        container = Composite(parent)
        layout = GridLayout()
        layout.num_columns = 4
        layout.margin_width = 0
        layout.margin_height = 0
        container.setLayout(layout)

        selection_listener = SelectionListener()

        # Local Gradle
        gradle_local_tooltip = "Use a local installation of Gradle. For best results, ensure that the version of this local Gradle matches the version specified on this wizard page's description."
        self.gradle_local_choice_button = Button(container)
        self.gradle_local_choice_button.add_selection_listener(selection_listener)
        self.gradle_local_choice_button.set_tool_tip_text(gradle_local_tooltip)

        gradle_local_dir_label = Label(container, text="Local installation directory:")
        self.gradle_local_dir_text = Text(container)
        self.gradle_local_dir_text.set_tool_tip_text(gradle_local_tooltip)
        grid_data = GridData()
        grid_data.horizontal_alignment = 1
        self.gradle_local_dir_text.setLayout_data(grid_data)

        gradl_local_dir_button = Button(container, text="...")
        gradl_local_dir_button.add_listener(selection_listener)

        # Gradle Wrapper
        gradle_wrapper_tooltip = "Use the Gradle Wrapper, which will automatically download the correct version of Gradle to use from the Internet."
        self.gradle_wrapper_choice_button = Button(container)
        self.gradle_wrapper_choice_button.add_selection_listener(selection_listener)
        self.gradle_wrapper_choice_button.set_tool_tip_text(gradle_wrapper_tooltip)

        gradle_wrapper_dir_label = Label(container, text="Gradle Wrapper")
        internet_label = Label(container, text="INTERNET CONNECTION REQUIRED", foreground_color='red')
        empty_grid_cell = Label(container)

        # Set default value from preferences
        last_gradle_distribution = GhidraProjectCreatorPreferences.get_ghidra_last_gradle_distribution()
        if isinstance(last_gradle_distribution, LocalGradleDistribution):
            self.gradle_local_choice_button.set_selection(True)
            local_gradle_distribution = last_gradle_distribution
            if local_gradle_distribution.location is not None:
                self.gradle_local_dir_text.set_text(local_gradle_distribution.location.abspath())
        elif isinstance(last_gradle_distribution, WrapperGradleDistribution) or isinstance(last_gradle_distribution, FixedVersionGradleDistribution):
            self.gradle_wrapper_choice_button.set_selection(True)
        else:
            self.gradle_local_choice_button.set_selection(True)

        validate()

    def set_visible(self, visible):
        super().set_visible(visible)

        if visible:
            project = self.project_page.get_ghidra_module_project()
            ghidra_folder = project.get_folder(GhidraProjectUtils.GHIDRA_FOLDER_NAME)
            ghidra_dir = ghidra_folder.location.to_file()
            try:
                application_layout = GhidraApplicationLayout(ghidra_dir)
                props = application_layout.application_properties
                self.gradle_version = props.get_property(ApplicationProperties.APPLICATION_GRADLE_MIN_PROPERTY)
                if self.gradle_version is not None and len(self.gradle_version) > 0:
                    self.setDescription(f"Configure Gradle. Version {self.gradle_version} is expected.")
            except IOException as e:
                EclipseMessageUtils.error("Unable to determine required Gradle version.")

    def get_gradle_distribution(self):
        if self.gradle_local_choice_button.get_selection():
            return GradleDistribution.for_local_installation(File(self.gradle_local_dir_text.get_text()))
        elif self.gradle_version is not None and len(self.gradle_version) > 0:
            return GradleDistribution.for_version(self.gradle_version)
        else:
            # This case should only happen if someone deleted the Gradle version from application.properties. In that case, we'll just try the standard wrapper and hope for the best.
            return GradleDistribution.from_build()

    def validate(self):
        message = None

        if self.gradle_local_choice_button.get_selection():
            path = self.gradle_local_dir_text.get_text().strip()
            dir = File(path)
            if len(path) == 0:
                message = "Path to local Gradle installation must be specified."
            elif not dir.exists():
                message = "Path to local Gradle installation does not exist."
            elif not dir.is_directory():
                message = "Path to local Gradle installation is not a directory."
            else if not File(dir, 'bin/gradle').exists():
                message = f"Path to local Gradle installation appears invalid. Missing gradle binary."

        if message is None:
            GhidraProjectCreatorPreferences.set_ghidra_last_gradle_distribution(self.get_gradle_distribution())
        else:
            GhidraProjectCreatorPreferences.set_ghidra_last_gradle_distribution(None)

        self.set_error_message(message)
        self.set_page_complete(message is None)
