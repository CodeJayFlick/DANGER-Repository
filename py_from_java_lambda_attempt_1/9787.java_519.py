Here is the translation of the Java code into Python:

```Python
from tkinter import *
import decimal

class DoubleRangeConstraintEditor:
    FLOATING_POINT_FORMAT = "0.##########;-0.##########"
    DISPLAY_FORMAT = "#,##0.##########;-#,##0.##########"

    def __init__(self, constraint):
        self.constraint = constraint
        self.lower_spinner = None
        self.upper_spinner = None
        self.info_label = None

    def build_inline_editor_component(self):
        min_value = self.constraint.get_min_value()
        max_value = self.constraint.get_max_value()

        panel = Frame(parent=None)
        panel.pack(fill=BOTH, expand=1)

        lower_spinner = create_spinner(min_value)
        upper_spinner = create_spinner(max_value)

        range_control_panel = Frame(panel)
        range_control_panel.pack(side=LEFT, fill=Y)

        range_control_panel.grid_columnconfigure(0, weight=1)
        range_control_panel.grid_columnconfigure(1, weight=1)

        range_control_panel.addWidget(lower_spinner)
        range_control_panel.addWidget(upper_spinner)

        info_label_number_format = decimal.DecimalFormat(self.DISPLAY_FORMAT)

        self.info_label = Label(panel, text="", justify=CENTER)
        self.info_label.pack(fill=BOTH, expand=1)

        return panel

    def create_spinner(self, value):
        step_size = 0.1
        spinner_model = SpinnerNumberModel(value, None, None, step_size)

        spinner = Spinbox(parent=None, from_=value - step_size, to=value + step_size)
        num_editor = NumberEditor(spinner.get())
        text_field = num_editor.get_text_field()
        text_field.set_validate_command(lambda: self.text_changed(spinner, text_field))

        return spinner

    def text_changed(self, spinner, text_field):
        try:
            value = float(text_field.get())
            if isinstance(value, int) and 0 <= value < 10**9:
                spinner.set(value)
            else:
                raise ValueError
        except (ValueError, TypeError):
            pass

    @staticmethod
    def increment(base, by):
        return base + by

    @staticmethod
    def decrement(base, by):
        return base - by

    def update_info_message(self, is_valid):
        if is_valid:
            start = self.lower_spinner.get()
            end = self.upper_spinner.get()

            delta = (end - start) * 1.0

            message = f"Range size: {self.info_label_number_format.format(delta)}"
            self.info_label.config(text=message)
        else:
            self.info_label.config(text=self.error_message)

    def update_editor_component(self):
        if has_editor_components():
            min_value = self.constraint.get_min_value()
            max_value = self.constraint.get_max_value()

            self.lower_spinner.set(min_value)
            self.upper_spinner.set(max_value)

        self.value_changed()

    @staticmethod
    def reset():
        value = (0.0, 0.0)
        return value

    @staticmethod
    def get_value_from_component():
        lower_value = float(self.lower_spinner.get())
        upper_value = float(self.upper_spinner.get())

        return ((lower_value), (upper_value))

    @staticmethod
    def check_editor_value_validity():
        is_lower_valid = self.has_valid_value(self.lower_spinner)
        is_upper_valid = self.has_valid_value(self.upper_spinner)

        if not is_lower_valid and not is_upper_valid:
            error_message = "Invalid lower and upper bounds!"
            return False

        if not is_lower_valid:
            error_message = "Invalid lower bounds!"
            return False
        if not is_upper_valid:
            error_message = "Invalid upper bounds!"
            return False

        if self.lower_spinner.get() > self.upper_spinner.get():
            error_message = "Upper bounds value must be greater than lower bounds!"
            return False

        return True

    @staticmethod
    def has_valid_value(spinner):
        try:
            text = str(float(spinner.get()))
            return True
        except (ValueError, TypeError):
            return False

# Testing methods
def get_lower_spinner(self):
    return self.lower_spinner

def get_upper_spinner(self):
    return self.upper_spinner
```

Please note that this is a direct translation of the Java code into Python. The original code seems to be part of a larger program and might not work as-is in a standalone Python environment.