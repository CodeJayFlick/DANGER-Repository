Here is the translation of the given Java code into equivalent Python:

```Python
class PreferenceState:
    PREFERENCE_STATE_NAME = "PREFERENCE_STATE"

    def __init__(self):
        super().__init__(PREFERENCE_STATE_NAME)

    @classmethod
    def from_element(cls, element):
        return cls(element)
```

Note that the `SaveState` class is not defined in this translation as it's a Java concept and doesn't have an equivalent in Python.