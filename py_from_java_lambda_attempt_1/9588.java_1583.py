Here is the translation of the Java interface into a Python class:

```Python
class FieldSelectionListener:
    def __init__(self):
        pass

    def selection_changed(self, selection: 'FieldSelection', trigger: 'EventTrigger'):
        """Called whenever the field selection changes."""
        # Add your code here to handle the selection change event.
```

Note that Python does not have a direct equivalent of Java's interface. Instead, we define a class with methods that are intended to be implemented by any subclass.