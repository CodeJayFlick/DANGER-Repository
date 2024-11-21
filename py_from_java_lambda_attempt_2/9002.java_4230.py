Here is the translation of the Java code into Python:

```Python
from abc import ABCMeta, abstractmethod
import re

class AbstractDoubleRangeFilter(metaclass=ABCMeta):
    def __init__(self, filter_name: str, min_value: float, max_value: float) -> None:
        self.filter_name = filter_name
        self.min_value = min_value
        self.max_value = max_value
        
        self.component = self.create_component()
        
    @abstractmethod
    def get_filterable_value(self, t):
        pass

    def create_lower_bound_field(self) -> None:
        self.lower_bound_field = FilterFormattedTextField(
            BoundedRangeDecimalFormatterFactory(self.max_value, self.min_value), 
            str(self.min_value)
        )
        self.lower_bound_field.name = f"Lower {self.filter_name} Filter Field"
        self.lower_bound_field.columns = 4
        self.lower_bound_field.minimum_size = self.lower_bound_field.get_preferred_size()
        self.lower_bound_field.horizontal_alignment = "RIGHT"

    def create_upper_bound_field(self) -> None:
        self.upper_bound_field = FilterFormattedTextField(
            BoundedRangeDecimalFormatterFactory(self.max_value, self.min_value), 
            str(self.max_value)
        )
        self.upper_bound_field.name = f"Upper {self.filter_name} Filter Field"
        self.upper_bound_field.columns = 4
        self.upper_bound_field.minimum_size = self.upper_bound_field.get_preferred_size()
        self.upper_bound_field.horizontal_alignment = "RIGHT"

    def create_component(self) -> object:
        self.create_lower_bound_field()
        self.create_upper_bound_field()

        lower_bound_input_verifier = BoundedRangeInputVerifier(
            self.lower_bound_field, True, self.max_value, self.min_value
        )
        upper_bound_input_verifier = BoundedRangeInputVerifier(
            self.upper_bound_field, False, self.max_value, self.min_value
        )

        self.lower_bound_field.set_input_verifier(lower_bound_input_verifier)
        self.upper_bound_field.set_input_verifier(upper_bound_input_verifier)

        panel = JPanel(HorizontalLayout())
        padding_border = BorderFactory.create_empty_border()
        outside_border = BorderFactory.create_bevel_border(BevelBorder.LOWERED)
        panel.border = BorderFactory.create_compound_border(outside_border, padding_border)

        filter_label = GDLabel(f"{self.filter_name} Filter: ")
        middle_label = GDLabel("to")

        panel.add(filter_label)
        panel.add(self.lower_bound_field)
        panel.add(middle_label)
        panel.add(self.upper_bound_field)

        notification_listener = status -> self.fire_status_changed(status)

        lower_bound_status_label = StatusLabel(self.lower_bound_field, self.min_value)
        upper_bound_status_label = StatusLabel(self.upper_bound_field, self.max_value)

        self.lower_bound_field.add_filter_status_listener(lower_bound_status_label)
        self.upper_bound_field.add_filter_status_listener(upper_bound_status_label)

        layered_pane = JLayeredPane()
        layered_pane.add(panel, 1)
        layered_pane.add(lower_bound_status_label, 2)
        layered_pane.add(upper_bound_status_label, 2)

        return panel

    def get_component(self) -> object:
        return self.component

    def clear_filter(self):
        self.lower_bound_field.text = str(self.min_value)
        self.upper_bound_field.text = str(self.max_value)

    def get_filter_status(self) -> FilterEditingStatus:
        lower_status = self.lower_bound_field.get_filter_status()
        upper_status = self.upper_bound_field.get_filter_status()

        if lower_status == FilterEditingStatus.ERROR or upper_status == FilterEditingStatus.ERROR:
            return FilterEditingStatus.ERROR

        if lower_status == FilterEditingStatus.APPLIED or upper_status == FilterEditingStatus.APPLIED:
            return FilterEditingStatus.APPLIED

        return FilterEditingStatus.NONE

    def passes_filter(self, t) -> bool:
        if self.lower_bound_field.get_filter_status() == FilterEditingStatus.ERROR or \
           self.upper_bound_field.get_filter_status() == FilterEditingStatus.ERROR:
            return True  # for an invalid filter state, we let all values through

        lower_bound_text = self.lower_bound_field.text
        upper_bound_text = self.upper_bound_field.text

        if not re.match(r"^-?\d+(\.\d+)?$", lower_bound_text):
            return False  # temporary transition; we will be called again

        filterable_value = self.get_filterable_value(t)
        if filterable_value < self.min_value:
            return False  # the filter value is lower than the lower range filter
        elif filterable_value > self.max_value:
            return False  # the filter value is higher than the upper range filter

        return True

    def write_config_state(self, save_state):
        state_key = self.get_state_key()
        values = [self.lower_bound_field.text, self.upper_bound_field.text]
        save_state.put_strings(state_key, values)

    def get_state_key(self) -> str:
        return f"{type(self).__name__}"

    def read_config_state(self, save_state):
        if not hasattr(save_state, "get_strings"):
            return

        state_key = self.get_state_key()
        values = save_state.get_strings(state_key)
        if values is None or len(values) != 2:
            return

        self.lower_bound_field.text = values[0]
        self.upper_bound_field.text = values[1]

    def get_upper_number(self):
        return self.upper_bound_to_double()

    def get_lower_number(self):
        return self.lower_bound_to_double()

    def lower_bound_to_double(self) -> float:
        if not re.match(r"^-?\d+(\.\d+)?$", self.lower_bound_field.text):
            return None

        try:
            return float(self.lower_bound_field.text)
        except ValueError:
            return None

    def upper_bound_to_double(self) -> float:
        if not re.match(r"^-?\d+(\.\d+)?$", self.upper_bound_field.text):
            return None

        try:
            return float(self.upper_bound_field.text)
        except ValueError:
            return None
```

Please note that this is a direct translation of the Java code into Python, and it may require some adjustments to work correctly in your specific use case.