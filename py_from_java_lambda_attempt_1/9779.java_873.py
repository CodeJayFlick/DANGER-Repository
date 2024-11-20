Here is the translation of the Java code into Python:

```Python
from tkinter import *
import stringutils as StringUtils

class BooleanConstraintEditor:
    def __init__(self, constraint):
        self.constraint = constraint
        self.combo_box = None

    def build_inline_editor_component(self):
        panel = Frame()
        panel.pack()

        combo_box = StringVar(value=['TRUE', 'FALSE'])
        combo_box.set('TRUE')
        box = OptionMenu(panel, combo_box)
        box.config(width=10)

        panel.pack_forget()
        return panel

    def get_value_from_component(self):
        value = self.combo_box.get()
        if value == 'TRUE':
            return True
        elif value == 'FALSE':
            return False
        else:
            raise ValueError('Invalid value')

    def update_editor_component(self):
        if hasattr(self, 'panel'):
            combo_box = StringVar(value=['TRUE', 'FALSE'])
            combo_box.set(str(getattr(self.constraint, 'getValue')))
            box = OptionMenu(self.panel, combo_box)
            box.config(width=10)

    def reset(self):
        self.combo_box.set('TRUE')

    def check_editor_value_validity(self):
        return True

    def update_info_message(self, is_valid):
        pass  # this editor does not have an info field

    def get_error_message(self):
        return ''

class BooleanMatchColumnConstraint:
    def __init__(self, value):
        self.value = value
```

Please note that Python's tkinter library doesn't support the exact equivalent of Java Swing. The code above is a simplified translation and may not work exactly as expected in your application.