class CreateGhidraScriptWizardPage:
    def __init__(self):
        self.selecttion = None
        self.script_folder_text = ''
        self.script_name_text = ''
        self.java_radioButton = False
        self.python_radioButton = True
        self.script_author_text = ''
        self.script_category_text = ''
        self.script_description_text = ''

    def create_control(self, parent):
        container = gtk.HBox()
        layout = gtk.GridLayout(3)
        container.set_layout(layout)

        # Source folder
        source_folder_label = gtk.Label("Script folder:")
        script_folder_text = gtk.Entry()
        script_folder_text.set_editable(False)
        if self.selecttion:
            script_folder_text.set_text(self.selecttion.get_path().toString())
        else:
            script_folder_text.set_text("")
        script_folder_button = gtk.Button("...")
        script_folder_button.connect('clicked', lambda x: (selection_dialog.open() == Window.OK) and
                                                  (script_folder_text.set_text(ResourcesPlugin.get_workspace().get_root().get_folder(selection_dialog.get_package_fragment_root().get_path()).get_full_path().toString())))

        # Script name
        script_name_label = gtk.Label("Script name:")
        script_name_text = gtk.Entry()
        if self.selecttion:
            script_name_text.set_text(self.selecttion.get_path().toString() + (self.java_radioButton and ".java" or ".py"))
        else:
            script_name_text.set_text("")
        new_label = gtk.Label("")  # empty grid cell

        # Script type
        script_type_group = gtk.VBox()
        java_radio_button = gtk.RadioButton("Java")
        python_radio_button = gtk.RadioButton("Python", group=java_radio_button)
        if self.java_radioButton:
            java_radio_button.set_active(True)

        new_label = gtk.Label("")  # empty grid cell

        # Script author
        script_author_label = gtk.Label("Script author:")
        script_author_text = gtk.Entry()
        if self.selecttion:
            script_author_text.set_text(self.selecttion.get_path().toString())
        else:
            script_author_text.set_text("")
        new_label = gtk.Label("")  # empty grid cell

        # Script category
        script_category_label = gtk.Label("Script category:")
        script_category_text = gtk.Entry()
        if self.selecttion:
            script_category_text.set_text(self.selecttion.get_path().toString())
        else:
            script_category_text.set_text("")
        new_label = gtk.Label("")  # empty grid cell

        # Script description
        script_description_label = gtk.Label("Script description:")
        script_description_text = gtk.Text()
        if self.selecttion:
            script_description_text.set_text(self.selecttion.get_path().toString())
        else:
            script_description_text.set_text("")
        new_label = gtk.Label("")  # empty grid cell

        container.pack_start(source_folder_label, False)
        container.pack_start(script_folder_text, True)
        container.pack_start(script_folder_button, False)

        container.pack_start(new_label, False)  # empty grid cell
        container.pack_start(script_name_label, False)
        container.pack_start(script_name_text, True)

        script_type_group.pack_start(java_radio_button, False)
        script_type_group.pack_start(python_radio_button, False)
        new_label = gtk.Label("")  # empty grid cell

        container.pack_start(new_label, False)  # empty grid cell
        container.pack_start(script_author_label, False)
        container.pack_start(script_author_text, True)

        container.pack_start(new_label, False)  # empty grid cell
        container.pack_start(script_category_label, False)
        container.pack_start(script_category_text, True)

        new_label = gtk.Label("")  # empty grid cell

        container.pack_start(new_label, False)  # empty grid cell
        container.pack_start(script_description_label, False)
        container.pack_start(script_description_text, True)

        self.set_control(container)

    def get_script_folder(self):
        if not script_folder_text.get_text().isEmpty():
            try:
                path = Path(script_folder_text.get_text())
                return ResourcesPlugin.get_workspace().get_root().get_folder(path)
            except IllegalArgumentException as e:
                # Fall through to return null
                pass

        return None

    def get_script_name(self):
        if self.selecttion and (self.java_radioButton or not self.python_radioButton):
            return script_name_text.get_text() + ".java"
        else:
            return script_name_text.get_text() + ".py"

    def get_script_author(self):
        return script_author_text.get_text()

    def get_script_category(self):
        return script_category_text.get_text()

    def get_script_description(self):
        return script_description_text.get_text().split("\n")

    def validate(self):
        message = None
        if not self.selecttion:
            message = "Script folder must be specified"
        elif not self.script_folder_text.get_text():
            message = "Script name must be specified"
        else:
            for char in BAD_START + BAD:
                if script_name_text.get_text().charAt(0) == char:
                    message = f"Script name cannot start with an invalid character: {BAD_START}{BAD}"
                    break
            if not self.selecttion and (BAD_START + BAD).chars().anyMatch(char -> script_name_text.get_text().indexOf(char) != -1):
                message = f"Script name cannot contain invalid characters: {BAD}"

        set_error_message(message)
        set_page_complete(message is None)

    def __str__(self):
        return "Create Ghidra Script Wizard Page"
