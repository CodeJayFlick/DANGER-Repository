Here is the translation of the Java interface `MeasurementMBean` into a Python class:

```python
class MeasurementMBean:
    def start_statistics(self):
        pass  # implementation not provided in this example

    def start_continuous_print_statistics(self):
        pass  # implementation not provided in this example

    def start_print_statistics_once(self):
        pass  # implementation not provided in this example

    def stop_print_statistic(self):
        pass  # implementation not provided in this example

    def stop_statistic(self):
        pass  # implementation not provided in this example

    def clear_statistical_state(self):
        pass  # implementation not provided in this example

    def change_operation_switch(self, operation_name: str, operation_state: bool) -> bool:
        return True  # default value for boolean operations

    @property
    def is_enable_stat(self) -> bool:
        return False  # default value for enable statistic flag

    @property
    def display_interval_in_ms(self) -> int:
        return 0  # default value for display interval in milliseconds

    @display_interval_in_ms.setter
    def set_display_interval_in_ms(self, display_interval_in_ms: int):
        pass  # implementation not provided in this example

    @property
    def operation_switch(self) -> dict:
        return {}  # default value for operation switch map
```

Note that the Python code does not include any actual implementations of the methods. The `pass` statement is used to indicate where the method should be implemented, but it does nothing when called.