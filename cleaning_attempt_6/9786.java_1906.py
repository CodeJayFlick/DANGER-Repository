class DoNothingColumnConstraintEditor:
    def __init__(self, constraint):
        self.constraint = constraint

    def reset(self):
        pass  # do nothing

    def get_error_message(self):
        return None  # no error message

    def get_value_from_component(self):
        return self.constraint

    def build_inline_editor_component(self):
        from tkinter import JPanel
        return JPanel()  # equivalent to a blank panel in Java

    def update_editor_component(self):
        pass  # do nothing

    def update_info_message(self, is_valid):
        pass  # do nothing

    def check_editor_value_validity(self):
        return True  # always valid
