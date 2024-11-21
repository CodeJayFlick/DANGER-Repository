class DummyConstraintEditor:
    def __init__(self, message):
        self.message = message

    def get_inline_component(self):
        from tkinter import Tk, Label, Panel
        root = Tk()
        error_label = Label(root, text="<html>" + "<b><font color='red'>" + self.message + "</font></b>", justify="left")
        panel = Panel(root)
        panel.add(error_label)
        return panel

    def get_detail_component(self):
        return None

    def get_value(self):
        return None

    def set_value(self, value):
        pass

    def reset(self):
        pass

    def has_valid_value(self):
        return False

    def get_error_message(self):
        return self.message

    def add_change_listener(self, listener):
        pass

    def remove_change_listener(self, listener):
        pass
