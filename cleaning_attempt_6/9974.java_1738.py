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
