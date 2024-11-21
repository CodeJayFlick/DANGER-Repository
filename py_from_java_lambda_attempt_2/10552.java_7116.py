Here is the translation of the Java interface `StatusListener` to a Python class:

```python
class StatusListener:
    def set_status_text(self, text):
        """Set the current status as type INFO"""
        pass  # Implement this method in your subclass

    def set_status_text(self, text: str, type: int) -> None:
        """Set the current status as the specified type"""
        pass  # Implement this method in your subclass

    def set_status_text(self, text: str, type: int, alert: bool) -> None:
        """Set the current status as the specified type with an optional alert"""
        pass  # Implement this method in your subclass

    def clear_status_text(self) -> None:
        """Clear the current status (same as set_status_text('') without being recorded)"""
        pass  # Implement this method in your subclass
```

Note that I've kept the Python methods abstract, meaning they don't have any implementation. This is because the original Java interface was also an abstract class with no implementation. In a real-world scenario, you would create concrete subclasses of `StatusListener` and implement these methods according to your specific needs.

Also, I didn't translate the Java comments as they are not directly translatable to Python (Python uses docstrings instead).