Here is the translation of the Java interface `XmlTracer` to a Python class:

```python
class XmlTracer:
    def __init__(self):
        pass

    def trace(self, locator: 'Locator', trace_message: str, throwable_if_available: Exception) -> None:
        """The trace callback. Please be quick.
        
        Args:
            locator (Locator): Locator, or None if not available
                (note: locator information may be inaccurate!)
            trace_message (str): The trace message
            throwable_if_available (Exception): An exception if we're encountering one (or None)
        """
        pass  # Implement the callback logic here
```

Note that I've used Python's type hinting to indicate the types of the method parameters, and also included a brief description of each parameter. The `pass` statement is just a placeholder for where you would implement the actual tracing logic in your Python code.