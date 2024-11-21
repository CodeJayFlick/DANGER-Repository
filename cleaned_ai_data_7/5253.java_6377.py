class DataTypeSelectionEditor:
    def __init__(self, serviceProvider, allowedDataTypes):
        self.dataTypeManagerService = serviceProvider
        self.allowedDataTypes = allowedDataTypes
        self.init()

    def init(self):
        self.selectionField = DropDownSelectionTextField(DataType)
        self.browseButton = ButtonPanelFactory.create_button(ButtonPanelFactory.BROWSE_TYPE)
        self.editorPanel = JPanel()
        self.editorPanel.setLayout(BoxLayout(self.editorPanel, BoxLayout.X_AXIS))
        self.editorPanel.add(self.selectionField)
        self.editorPanel.add(Box.create_horizontal_strut(5))
        self.editorPanel.add(self.browseButton)

    def get_cell_editor_value(self):
        return self.selectionField.get_selected_value()

    def set_cell_editor_value(self, dataType):
        self.selectionField.set_selected_value(dataType)
        self.navigation_direction = None

    def add_document_listener(self, listener):
        self.selectionField.get_document().add_document_listener(listener)

    def remove_document_listener(self, listener):
        self.selectionField.get_document().remove_document_listener(listener)

    def set_consume_enter_key_press(self, consume):
        self.selectionField.set_consume_enter_key_press(consume)

    def get_editor_component(self):
        return self.editorPanel

    def validate_user_selection(self):
        if not self.is_valid_data_type():
            return self.parse_data_type_text_entry()
        return True

    def contains_valid_data_type(self):
        try:
            return self.is_valid_data_type()
        except InvalidDataTypeException as e:
            return False

    def is_valid_data_type(self):
        selected_data_type = self.selectionField.get_selected_value()
        if selected_data_type and self.selectionField.get_text() == selected_data_type.name:
            DataTypeParser.ensure_is_allowable_type(selected_data_type, self.allowedDataTypes)
            return True
        return False

    def get_data_type_root_for_current_text(self):
        data_type = self.selectionField.get_selected_value()
        if data_type:
            current_text = self.selectionField.get_text()
            selected_base_data_type = DataTypeUtils.get_named_base_data_type(data_type)
            if current_text.startswith(selected_base_data_type.name):
                return selected_base_data_type
        return None

    def parse_data_type_text_entry(self):
        if not self.selectionField.get_text().strip():
            # no need to invoke parser on empty string
            return False

        new_data_type = None
        try:
            new_data_type = DataTypeParser.parse(
                self.selectionField.get_text(), 
                self.get_data_type_root_for_current_text()
            )
        except CancelledException as e:
            return False

        if new_data_type:
            self.selectionField.set_selected_value(new_data_type)
            return True
        return False

    def show_data_type_browser(self):
        data_type = self.dataTypeManagerService.get_data_type(self.initially_selected_tree_path)
        if data_type:
            self.set_cell_editor_value(data_type)
            self.selectionField.request_focus()

class DropDownSelectionTextField:
    pass  # This class is not implemented in the given Java code

class ButtonPanelFactory:
    BROWSE_TYPE = "BROWSE"

class BoxLayout:
    def __init__(self, panel, axis):
        pass  # This class is not implemented in the given Java code

class JPanel:
    pass  # This class is not implemented in the given Java code

class DropDownSelectionDataModel:
    pass  # This class is not implemented in the given Java code
