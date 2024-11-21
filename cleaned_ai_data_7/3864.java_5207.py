class ParameterDataTypeCellEditor:
    def __init__(self, dialog, service):
        self.dialog = dialog
        self.service = service

    def getTableCellEditorComponent(self, table1, value, isSelected, row, column):
        self.init()
        dt = value
        editor.set_cell_editor_value(dt)
        return self.editor_panel

    def init(self):
        self.editor = DataTypeSelectionEditor(self.service, DataTypeParser.AllowedDataTypes.ALL)
        self.editor.set_tab_commits_edit(True)
        self.editor.consume_enter_key_press(False)  # we want the table to handle Enter key presses
        text_field = self.editor.get_drop_down_text_field()
        self.editor.add_cell_editor_listener(lambda e: self.cancel_cell_editing())
        self.editor.add_cell_editor_listener(lambda e: self.stop_cell_editing())

        data_type_chooser_button = JButton("...")  # force a small button for the table's cell editor
        data_type_chooser_button.addActionListener(
            lambda e: SwingUtilities.invokeLater(
                lambda: (
                    dt = self.service.get_data_type(None)
                    if dt is not None:
                        self.editor.set_cell_editor_value(dt)
                        self.editor.stop_cell_editing()
                    else:
                        self.editor.cancel_cell_editing()
                )
            )
        )

        focus_listener = FocusAdapter()  # handle focus events
        text_field.add_focus_listener(focus_listener)

        self.editor_panel = JPanel(FlowLayout())
        self.editor_panel.add(text_field, BorderLayout.CENTER)
        self.editor_panel.add(data_type_chooser_button, BorderLayout.EAST)

    def get_text_field(self):
        return self.text_field

    def get_chooser_button(self):
        return self.data_type_chooser_button

    def get_cell_editor_value(self):
        return dt

    def stop_cell_editing(self):
        try:
            data_type = self.editor.get_cell_editor_value_as_data_type()
            if data_type is None:
                text = self.editor.get_cell_editor_value_as_text()
                self.dialog.set_status_text("Invalid data type: " + text, MessageType.ERROR)
                return False
            elif data_type == dt:
                self.fire_editing_canceled()  # user picked the same datatype
            else:
                dt = data_type
                self.fire_editing_stopped()

        except IllegalArgumentException as ex:
            text = self.editor.get_cell_editor_value_as_text()
            self.dialog.set_status_text("Invalid data type: " + text, MessageType.ERROR)
            return False

        return True

    def is_cell_editable(self, an_event):
        if isinstance(an_event, MouseEvent) and an_event.get_click_count() >= 2:
            return True
        else:
            return False

class JButton:
    pass

class JPanel:
    pass

class FocusAdapter:
    pass

class MessageType:
    ERROR = "ERROR"

def SwingUtilities.invokeLater(func):
    # This is a placeholder for the actual implementation of invokeLater.
    func()

# These are placeholders for the actual implementations of these methods
def cancel_cell_editing():
    pass

def stop_cell_editing():
    pass

def fire_editing_canceled():
    pass

def fire_editing_stopped():
    pass
