Here is the translation of the Java code into Python:

```Python
class StringConstraintEditor:
    def __init__(self, constraint: str, error_message: str):
        self.constraint = constraint
        self.error_message = error_message

    def build_inline_editor_component(self) -> tuple:
        panel = JPanel()
        text_field = JTextField()
        text_field.get_document().add_undoable_edit_listener(lambda e: self.value_changed())
        
        panel.add(text_field, BorderLayout.CENTER)

        info_label = GDHtmlLabel("abc")  # temporary text in the label so that it sizes properly
        info_label.set_foreground_color(Color.RED)
        info_label.set_horizontal_alignment(SwingConstants.CENTER)
        panel.add(info_label, BorderLayout.SOUTH)
        return panel

    def get_value_from_component(self) -> str:
        new_pattern_string = text_field.get_text().strip()
        return self.constraint.copy(new_pattern_string)

    def reset(self):
        self.set_value(self.constraint.copy(""))

    def check_editor_value_validity(self) -> bool:
        return self.constraint.is_valid_pattern_string(text_field.get_text().strip())

    def update_info_message(self, is_valid: bool):
        status = f"{'&nbsp;' if is_valid else self.error_message}"
        info_label.set_text(status)

    def get_error_message(self) -> str:
        if self.has_valid_value():
            return ""
        return "Please enter a pattern to match (You may use * and ? globbing characters)"

    def update_editor_component(self):
        if self.has_editor_components():
            text_field.set_text(self.constraint.get_pattern_string())
            text_field.set_caret_position(0)

class JPanel:
    pass

class JTextField:
    def __init__(self):
        self.document = Document()

    @property
    def get_document(self) -> 'Document':
        return self.document

    @property
    def get_text(self) -> str:
        # implement this method to get the text from the field
        pass

    def set_caret_position(self, position: int):
        # implement this method to set the caret position in the field
        pass


class GDHtmlLabel:
    def __init__(self, initial_text: str):
        self.text = initial_text

    @property
    def get_foreground_color(self) -> Color:
        return None  # implement this method to get the foreground color of the label

    @get_foreground_color.setter
    def set_foreground_color(self, value: Color):
        pass

    @property
    def get_horizontal_alignment(self) -> int:
        return SwingConstants.CENTER  # implement this method to get the horizontal alignment of the label

    @get_horizontal_alignment.setter
    def set_horizontal_alignment(self, value: int):
        pass


class Document:
    def add_undoable_edit_listener(self, listener):
        pass


# usage example:

constraint = "your_constraint_here"
error_message = "your_error_message_here"

editor = StringConstraintEditor(constraint, error_message)
panel = editor.build_inline_editor_component()
```

Please note that this is a direct translation of the Java code into Python. You may need to adjust it according to your specific requirements and environment.