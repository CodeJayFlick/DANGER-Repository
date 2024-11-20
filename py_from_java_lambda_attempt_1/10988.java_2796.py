Here is the translation of the Java interface `BackgroundCommandListener` into a Python class:

```python
class BackgroundCommandListener:
    def __init__(self):
        pass

    def command_completed(self, cmd):
        """Notification that the given BackgroundCommand has completed."""
        # Your code here...
```

Note that in Python, we don't have an explicit `public` keyword like Java does. Instead, everything is public by default unless it's inside a class or function and not indented.

Also, I've used underscores instead of camelCase for the method name to follow PEP 8 conventions.