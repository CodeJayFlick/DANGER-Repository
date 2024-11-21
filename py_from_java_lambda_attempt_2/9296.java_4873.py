Here's your Java enum translated into Python:

```Python
class KeyBindingType:
    UNSUPPORTED = "UNSUPPORTED"
    INDIVIDUAL = "INDIVIDUAL"
    SHARED = "SHARED"

    def supports_key_bindings(self):
        return self != KeyBindingType.UNSUPPORTED

    def is_shared(self):
        return self == KeyBindingType.SHARED

    def is_managed(self):
        return self == KeyBindingType.INDIVIDUAL
```

This Python class has the same functionality as your Java enum, but it's implemented using a class with static variables and methods instead of an enum.