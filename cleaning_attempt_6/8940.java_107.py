from tkinter import *

class CheckBoxInfo:
    def __init__(self, checkbox):
        self.checkbox = checkbox

    def set_selected(self, b):
        self.checkbox.select()

    def get_selected(self):
        return self.checkbox.instate((SELECT, True))

    def get_checkbox(self):
        return self.checkbox

    def matches_status(self, t):  # abstract method
        raise NotImplementedError("Must be implemented by subclass")

    def __str__(self):
        return str(self.checkbox.cget('text'))
