Here is the translation of the given Java interface into a Python class:

```Python
class BooleanSettingsDefinition:
    def __init__(self):
        pass

    def get_value(self, settings: dict) -> bool:
        """gets the value for this SettingsDefinition given a Settings object."""
        raise NotImplementedError("Subclasses must implement this method")

    def set_value(self, settings: dict, value: bool) -> None:
        """Sets the given value into the given settings object using this settingsDefinition as the key."""
        raise NotImplementedError("Subclasses must implement this method")
```

Note that in Python, we don't have a direct equivalent of Java's interface. Instead, we can use abstract base classes (ABCs) to achieve similar functionality. In this case, I've used an ABC with two abstract methods (`get_value` and `set_value`) which subclasses must implement.