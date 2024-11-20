Here is the translation of the Java code to Python:
```
import datetime
from typing import Any

class DefaultTimestampRenderer:
    def get_table_cell_renderer_component(self, data: Any) -> Any:
        label = super().get_table_cell_renderer_component(data)
        value = data.get_value()
        
        if value is not None:
            label.set_text(datetime.datetime.strftime(value, "%Y-%m-%d %H:%M:%S"))
        
        return label

    def get_filter_string(self, t: Any, settings: Any) -> str:
        return datetime.datetime.strftime(t, "%Y-%m-%d %H:%M:%S")

    def get_column_constraint_filter_mode(self) -> int:
        # This allows for text filtering in the table and date filtering on columns
        return 1

# Example usage:
renderer = DefaultTimestampRenderer()
data = {"value": datetime.datetime.now()}
label = renderer.get_table_cell_renderer_component(data)
print(label.get_text())  # Output: current timestamp
```
Note that I've used Python's built-in `datetime` module to handle date and time formatting, as well as the `super()` function to call the parent class's method. The rest of the code is straightforward translations from Java to Python.

Also, please note that this translation assumes a basic understanding of both Java and Python programming languages. If you're new to one or both languages, it may be helpful to review their respective syntaxes before attempting to translate code between them.