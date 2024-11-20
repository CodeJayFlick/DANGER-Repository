import tkinter as tk

class IntegerFormatterFactory:
    def __init__(self, allows_negative_input=False):
        self.formatter = tk.IntValidator()

    def set_formatter(self, formatter=None, allows_negative_input=False):
        if allows_negative_input:
            self.formatter.set_invalid(True)
        else:
            self.formatter.set_invalid(False)

    def get_formatter(self):
        return self.formatter

# Example usage
factory = IntegerFormatterFactory(allows_negative_input=True)
formatter = factory.get_formatter()
