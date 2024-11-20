from datetime import date, timedelta
import calendar

class DateRangeConstraintEditor:
    def __init__(self, constraint):
        self.constraint = constraint
        if not self.is_valid_date(self.constraint.min_value):
            self.reset()

    @property
    def current_constraint(self):
        return self.constraint

    def init_lower_spinner(self, value, range_min, range_max):
        lower_spinner_model = LocalDateSpinnerModel(value, range_min, range_max, calendar.DAY_OF_MONTH)
        lower_spinner = DateSpinner(lower_spinner_model, 'yyyy-MM-dd')
        lower_spinner.get_spinner().set_name('lower.date.spinner')

        lower_spinner.add_change_listener(self.value_changed)

    def init_upper_spinner(self, value, range_min, range_max):
        upper_spinner_model = LocalDateSpinnerModel(value, range_min, range_max, calendar.DAY_OF_MONTH)
        upper_spinner = DateSpinner(upper_spinner_model, 'yyyy-MM-dd')
        upper_spinner.get_spinner().set_name('upper.date.spinner')

        upper_spinner.add_change_listener(self.value_changed)

    def build_inline_editor_component(self):
        panel = JPanel()
        min_value = self.constraint.min_value
        max_value = self.constraint.max_value

        self.init_lower_spinner(min_value, date.today() - timedelta(days=30), date.today() + timedelta(days=30))
        self.init_upper_spinner(max_value, date.today() - timedelta(days=30), date.today() + timedelta(days=30))

        control_panel = JPanel()
        control_panel.add(lower_spinner.get_spinner())
        control_panel.add(upper_spinner.get_spinner())

        panel.add(control_panel)

        info_label = GDHtmlLabel()
        info_label.set_foreground_color(Color.GRAY)
        info_label.set_horizontal_alignment(SwingConstants.CENTER)
        panel.add(info_label)

        return panel

    def update_info_message(self, is_valid):
        if is_valid:
            start_date = lower_spinner_model.get_value()
            end_date = upper_spinner_model.get_value()

            days = (end_date - start_date).days + 1
            info_label.set_text(f"Range Size: {days} days")
        else:
            info_label.set_text(self.error_message)

    def reset(self):
        min_val = date.today() - timedelta(days=365)
        max_val = date.today()

        self.constraint.copy(min_val, max_val)
        self.update_editor_component()

    def update_editor_component(self):
        min_value = self.constraint.min_value
        lower_spinner_model.set_value(min_value)

        max_value = self.constraint.max_value
        upper_spinner_model.set_value(max_value)

        self.value_changed()
        return

    @property
    def error_message(self):
        if not has_valid_value(lower_spinner) and not has_valid_value(upper_spinner):
            return "Invalid lower and upper bounds!"
        elif not has_valid_value(lower_spinner):
            return "Invalid lower bounds!"
        elif not has_valid_value(upper_spinner):
            return "Invalid upper bounds!"

    def check_editor_value_validity(self):
        if not self.is_valid_date(lower_spinner_model.get_value()) or not self.is_valid_date(upper_spinner_model.get_value()):
            self.error_message = "Invalid date range"
            return False
        else:
            return True

    @property
    def valid_input_color(self):
        # Define your color here, for example: '#00FF00'
        pass

    @property
    def invalid_input_color(self):
        # Define your color here, for example: '#FF0000'
        pass


class LocalDateSpinnerModel:
    def __init__(self, value, range_min, range_max, day_of_month):
        self.value = value
        self.range_min = range_min
        self.range_max = range_max

    @property
    def get_value(self):
        return self.value

    def set_value(self, new_value):
        self.value = new_value


class DateSpinner:
    def __init__(self, model, date_pattern):
        self.model = model
        self.date_field = LocalDateTextField()
        self.get_spinner()

    @property
    def get_spinner(self):
        return self.spinner

    def add_change_listener(self, listener):
        pass  # Add your change listener here


class JPanel:
    def __init__(self, layout=None):
        if layout is None:
            layout = VerticalLayout(2)

    def add(self, component):
        pass  # Add the component to this panel


def has_valid_value(spinner):
    text_field = spinner.date_field.get_text_field()
    value_string = str(spinner.model.value)
    return value_string == text_field.get_text()


class GDHtmlLabel:
    def __init__(self):
        pass

    @property
    def set_foreground_color(self, color):
        pass  # Set the foreground color of this label


def format_status(message, is_error):
    if is_error:
        return f"<font color='red'>{message}</font>"
    else:
        return message


class LocalDateTextField:
    def __init__(self):
        self.text_field = None

    @property
    def get_text_field(self):
        return self.text_field

    def set_text_field(self, text_field):
        self.text_field = text_field


def is_valid_date(date):
    if date == DateColumnConstraintProvider.DEFAULT_DATE:
        return False
    else:
        return True


class RangeColumnConstraint:
    pass  # Define your range column constraint class here


# Usage example:

constraint = RangeColumnConstraint()
editor = DateRangeConstraintEditor(constraint)
panel = editor.build_inline_editor_component()

