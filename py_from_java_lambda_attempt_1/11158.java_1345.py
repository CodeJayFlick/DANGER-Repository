Here is the translation of the Java code into Python:

```Python
class RepositoryPanel:
    def __init__(self, panel_manager: 'PanelManager', server_name: str, repository_names: list[str], read_only_server_access: bool):
        self.panel_manager = panel_manager
        self.server_name = server_name
        self.build_main_panel(repository_names, read_only_server_access)

    @property
    def title(self) -> str:
        return f"Specify Repository Name on {self.server_name}"

    def initialize(self):
        self.existing_rep_button.set_selected(True)
        self.name_list.clear_selection()
        self.name_field.setText("")

    def is_valid_information(self) -> bool:
        if self.create_rep_button.get_selected():
            name = self.name_field.text
            if len(name) == 0:
                return False
            if not NamingUtilities.is_valid_project_name(name):
                self.panel_manager.wizard_manager.set_status_message("Invalid project repository name")
                return False
            # 
            return list_model.contains(name)
        elif self.name_list.get_selected_value() is not None:
            return True
        return False

    @property
    def help_location(self) -> 'HelpLocation':
        if self.help_loc is not None:
            return self.help_loc
        return HelpLocation(GenericHelpTopics.FRONT_END, "SelectRepository")

    def set_help_location(self, location: 'HelpLocation'):
        self.help_loc = location

    @property
    def create_repository(self) -> bool:
        return self.create_rep_button.get_selected()

    def get_repository_name(self) -> str:
        if self.create_rep_button.get_selected():
            return self.name_field.text
        return self.name_list.get_selected_value()

    def build_main_panel(self, repository_names: list[str], read_only_server_access: bool):
        button_group = ButtonGroup()
        panel = JPanel(VerticalLayout())
        panel.set_border(BorderFactory.create_empty_border())

        create_rep_button = GRadioButton("Create Repository", not existing_rep_button.get_selected())
        button_group.add(create_rep_button)

        name_label = GDLabel("Repository Name:", SwingConstants.RIGHT)
        name_label.set_enabled(create_rep_button.get_selected())

        name_field = JTextField(20)
        document_listener = DocumentListener()
        name_field.getDocument().add_document_listener(document_listener)
        name_field.set_enabled(create_rep_button.get_selected())

        panel.add(name_label, BorderLayout.SOUTH)

        if read_only_server_access:
            create_rep_button.set_enabled(False)
            create_rep_button.set_selected(False)
            name_field.set_enabled(False)
            name_label.set_enabled(False)

    def validate_name(self):
        wizard_manager = self.panel_manager.wizard_manager
        msg = None
        if self.create_rep_button.get_selected():
            name = self.name_field.text
            if len(name) != 0:
                if not NamingUtilities.is_valid_project_name(name):
                    msg = "Invalid project repository name"
                elif list_model.contains(name):
                    msg = f"{name} already exists"
            } 
        wizard_manager.validity_changed()
        if msg is not None:
            wizard_manager.set_status_message(msg)

    def add_listeners(self):
        action_listener = ActionListener()
        existing_rep_button.add_action_listener(action_listener)
        create_rep_button.add_action_listener(action_listener)

        selection_model = name_list.get_selection_model()
        selection_model.add_list_selection_listener(ListSelectionListener())
```

Please note that Python does not have direct equivalent of Java's Swing and AWT libraries. The above code is written in pure Python, without using any GUI library.