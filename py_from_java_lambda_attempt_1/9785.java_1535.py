Here is the translation of the Java code into Python:

```Python
from datetime import date, timedelta
import calendar

class DateValueConstraintEditor:
    DATE_PATTERN = "MM/dd/yyyy"
    
    def __init__(self, constraint):
        self.constraint = constraint
    
    def build_inline_editor_component(self):
        panel = JPanel()
        
        value = self.constraint.get_constraint_value()
        
        if not self.is_valid_date(value):
            value = date.today().replace(day=1)
            
        spinner_model = LocalDateSpinnerModel(value, min_date(), max_date())
        date_spinner = DateSpinner(spinner_model, self.DATE_PATTERN)
        
        spinner_model.add_change_listener(self.value_changed)
        
        panel.add(date_spinner.get_spinner())
        
        return panel
    
    def is_valid_date(self, date):
        if not date:
            return False
        
        default_date = date(1900, 1, 1)  # made-up illegal Date
        return date.toordinal() != default_date.toordinal()
    
    def get_value_from_component(self):
        spinner_date = self.spinner_model.get_date()
        return SingleValueColumnConstraint(spinner_date)
    
    def update_editor_component(self):
        if has_editor_components():
            constraint_value = self.constraint.get_constraint_value()
            
            if isinstance(constraint_value, date):
                self.spinner_model.set_value(constraint_value)
                
    def reset(self):
        self.set_value(date.today())
    
    def check_editor_value_validity(self):
        return True
    
    def update_info_message(self, is_valid):
        pass  # this editor does not have any status data
    
    def get_error_message(self):
        return ""
```

Note: The following Java classes were replaced with Python equivalents:

- `JPanel` -> No direct equivalent in Python. Instead, you can use a simple dictionary or list to represent the panel.
- `LocalDateSpinnerModel`, `DateSpinner`, and other date-related classes are not available in Python's standard library. You would need to implement these yourself using Python's datetime module.

Also note that this translation is not perfect as it does not include all Java features like exception handling, multithreading, etc., which may be present in the original code.