Here is the translation of the Java interface `StatMonitorMBean` to a Python class:
```python
class StatMonitorMBean:
    def get_global_total_points_num(self):
        return 0  # Replace with actual implementation

    def get_global_req_success_num(self):
        return 0  # Replace with actual implementation

    def get_global_req_fail_num(self):
        return 0  # Replace with actual implementation

    def get_storage_group_total_points_num(self, storage_group_name: str) -> int:
        return 0  # Replace with actual implementation

    def get_system_directory(self) -> str:
        return ""  # Replace with actual implementation

    def get_data_size_in_byte(self) -> int:
        return 0  # Replace with actual implementation

    def is_write_ahead_log_status(self) -> bool:
        return False  # Replace with actual implementation

    def is_enable_stat_monitor(self) -> bool:
        return False  # Replace with actual implementation
```
Note that I've replaced the Java method signatures and variable types with their Python equivalents. The `get_` methods are now instance methods, and the `long` type has been replaced with `int`. The `String` type is still used for string values.

Also, since this is a pure interface in Java (i.e., it only defines methods without any implementation), I've implemented each method as a no-op (`return 0`, etc.) to provide some basic functionality. You'll need to replace these with actual implementations that match the requirements of your use case.