class UnsignedLongConstraintEditor:
    MAX_VALUE = "ffffffffffffffff"

    def __init__(self, constraint):
        self.constraint = constraint

    def build_inline_editor_component(self):
        panel = JPanel()
        value = self.constraint.get_constraint_value()

        field = IntegerTextField(16, 0)
        field.set_hex_mode()
        field.set_allow_negative_values(False)
        field.set_max_value(MAX_VALUE)
        field.add_change_listener(lambda e: self.value_changed())

        panel.add(field.get_component(), BorderLayout.CENTER)
        status_label = GDHtmlLabel()
        status_label.set_foreground(Color.RED)
        status_label.set_horizontal_alignment(SwingConstants.CENTER)

        return panel

    def reset(self):
        new_value = BigInteger.ZERO
        self.constraint.copy(new_value)

    def get_value_from_component(self):
        return self.constraint.copy(field.get_value())

    def update_editor_component(self):
        if has_editor_components():
            constraint_value = self.constraint.get_constraint_value()
            field.set_value(constraint_value)

    def check_editor_value_validity(self):
        return field.get_value() is not None

    def update_info_message(self, is_valid):
        status = format_status(is_valid and "&nbsp;" or "Please enter a value.", True)
        status_label.set_text(status)

    def get_error_message(self):
        return ""

class JPanel:
    pass

class IntegerTextField:
    def __init__(self, width, height):
        self.width = width
        self.height = height

    def set_hex_mode(self):
        pass

    def set_allow_negative_values(self, allow_negative_values):
        self.allow_negative_values = allow_negative_values

    def set_max_value(self, max_value):
        self.max_value = max_value

    def add_change_listener(self, listener):
        pass

class GDHtmlLabel:
    def __init__(self):
        pass

    def set_foreground(self, color):
        self.foreground = color

    def set_horizontal_alignment(self, alignment):
        self.horizontal_alignment = alignment
