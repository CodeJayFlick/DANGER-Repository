Here is the translation of the Java interface into a Python class:

```Python
class DebuggerConsoleService:
    def __init__(self):
        pass

    def log(self, icon: str, message: str) -> None:
        """Log a message to the console"""
        # Implementation left out for brevity. In real code, you would likely want to handle icons and messages differently.

    def log(self, icon: str, message: str, context: dict) -> None:
        """Log an actionable message to the console"""
        self.log(icon, message)

    def remove_from_log(self, context: dict) -> None:
        """Remove an actionable message from the console"""
        # Implementation left out for brevity. In real code, you would likely want to handle contexts differently.

    def log_contains(self, context: dict) -> bool:
        """Check if the console contains an actionable message for the given context"""
        return True  # Replace with actual implementation

    def add_resolution_action(self, action: callable) -> None:
        """Add an action which might be applied to an actionable log message"""
        pass  # Implementation left out for brevity. In real code, you would likely want to handle actions differently.

    def remove_resolution_action(self, action: callable) -> None:
        """Remove an action"""
        pass  # Implementation left out for brevity. In real code, you would likely want to handle actions differently.
```

Note that Python does not have direct equivalents of Java's `@ServiceInfo` and `extends DebuggerConsoleLogger`, so I've omitted those parts in the translation.