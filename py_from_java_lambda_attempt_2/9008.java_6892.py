Here's your Java code translated into Python:

```Python
class LengthFilter:
    DEFAULT_FILTER_VALUE = 0
    
    def __init__(self):
        self.component = self.create_component()
        
    def create_component(self):
        label = "Length Filter: "
        default_value = str(DEFAULT_FILTER_VALUE)
        text_field = FilterFormattedTextField(IntegerFormatterFactory(False), default_value)
        text_field.name = "Length Filter Field"  # for debugging
        text_field.input_verifier = IntegerInputVerifier()
        text_field.horizontal_alignment = SwingConstants.RIGHT
        
        panel = JPanel(BorderLayout())
        padding_border = BorderFactory.createEmptyBorder(1, 5, 1, 5)
        outside_border = BorderFactory.createBevelBorder(BevelBorder.LOWERED)
        panel.border = BorderFactory.createCompoundBorder(outside_border, padding_border)
        
        panel.add(JLabel(label), BorderLayout.WEST)
        panel.add(text_field, BorderLayout.EAST)
        
        status_label = StatusLabel(text_field, default_value)
        text_field.filter_status_listener.append(status_label)
        text_field.filter_status_listener.append(lambda status: self.fire_status_changed(status))
        layered_pane = JLayeredPane()
        layered_pane.add(panel, 1)  # BASE_ COMPONENT_LAYER
        layered_pane.add(status_label, 2)  # HOVER_COMPONENT_LAYER
        
    def get_component(self):
        return self.component
    
    def clear_filter(self):
        text_field.text = str(DEFAULT_FILTER_VALUE)
    
    def filter_status(self):
        return text_field.filter_status()
    
    def passes_filter(self, t):
        if not text_field.text or text_field.text.strip() == "":
            return True
        
        length_filter = int(text_field.text)
        score = t.source_length
        if score < length_filter:
            return False  # the match's score is lower than the filter
        
        score = t.destination_length
        if score >= length_filter:
            return True  # the match's score is higher than the filter
        
        return False  # the value is below the cutoff
    
    def get_filter_shortcut_state(self):
        text_field_text = text_field.text.strip()
        if not text_field_text or str(DEFAULT_FILTER_VALUE) == text_field_text:
            return FilterShortcutState.ALWAYS_PASSES
        else:
            return FilterShortcutState.REQUIRES_CHECK
    
    @staticmethod
    def is_default_value(text_field_text):
        return DEFAULT_FILTER_VALUE == int(text_field_text)
    
    def write_config_state(self, save_state):
        save_state.put_string("state_key", text_field.text)
    
    @staticmethod
    def get_state_key():
        return LengthFilter.__name__
    
    def read_config_state(self, save_state):
        text_field.text = save_state.get_string(LengthFilter.get_state_key(), "0")
    
    def to_integer(self):
        s = text_field.text
        if not s:
            return None
        
        try:
            return int(s)
        except ValueError:
            return None
    
    @staticmethod
    def is_sub_filter_of(other_filter):
        if not isinstance(other_filter, LengthFilter):
            return False
        
        other_length_filter = other_filter
        value = self.to_integer()
        other_value = other_length_filter.to_integer()
        
        if value == other_value:
            return True
        
        if value is None or other_value is None:
            return False
        
        # This filter is a minimum length filter. If we are a larger minimum length, then 
        # we are within the bounds of the smaller minimum length.
        result = value - other_value
        return result > 0  # our value is larger; we are a sub-filter

class FilterShortcutState:
    ALWAYS_PASSES = "ALWAYS_PASSES"
    REQUIRES_CHECK = "REQUIRES_CHECK"

class IntegerInputVerifier:
    def verify(self, input):
        try:
            int(input)
            return True
        except ValueError:
            return False

class StatusLabel:
    def __init__(self, text_field, default_value):
        self.text_field = text_field
        self.default_value = str(default_value)

# Note: The following classes are not defined in the provided Java code.
# They were added to make the Python translation work correctly.

class JPanel:
    pass

class JLabel:
    pass

class JLayeredPane:
    pass

class FilterFormattedTextField:
    def __init__(self, integer_formatter_factory, default_value):
        self.integer_formatter_factory = integer_formatter_factory
        self.default_value = str(default_value)

    @property
    def text(self):
        return self._text

    @text.setter
    def text(self, value):
        self._text = value

class IntegerFormatterFactory:
    def __init__(self, boolean):
        pass

# Note: The following classes are not defined in the provided Java code.
# They were added to make the Python translation work correctly.

if __name__ == "__main__":
    length_filter = LengthFilter()
```

Please note that this is a direct translation of your Java code into Python. It may require some adjustments based on how you plan to use it and whether there are any differences in behavior between Java and Python.