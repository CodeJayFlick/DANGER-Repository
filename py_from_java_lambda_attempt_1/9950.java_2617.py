Here is the translation of the Java interface into Python:

```
class WizardPanelListener:
    def validity_changed(self):
        """Notification that something on the panel changed."""
        pass  # Implement this method in your subclass

    def set_status_message(self, msg: str) -> None:
        """Notification to set a status message.
        
        Args:
            msg (str): The message
        """
        pass  # Implement this method in your subclass
```

Note that I've used Python's convention for docstrings and added type hints where possible. In Java, the interface methods are declared with `public`, but in Python, we don't need to specify access modifiers since everything is public by default.