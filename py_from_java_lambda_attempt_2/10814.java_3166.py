Here's the translation of the given Java interface into a Python equivalent:

```Python
class GraphSatelliteListener:
    def __init__(self):
        pass

    def satellite_visibility_changed(self, docked: bool, visible: bool) -> None:
        """
        Called when the visibility and/or docked state of the watched satellite changes.

        Args:
            docked (bool): True if the satellite is now docked.
            visible (bool): True if the satellite is now visible.
        """
        pass
```

In this translation, I've used Python's class-based approach to define an interface. The `__init__` method is not necessary in this case since it doesn't do anything. The actual method that needs to be implemented by any class implementing this interface (`satellite_visibility_changed`) has been defined with the same parameters and return type as its Java counterpart, but without the need for explicit exception handling or checked exceptions.