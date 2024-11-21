Here is the translation of the Java interface `EnumSettingsDefinition` into a Python class:

```python
class EnumSettingsDefinition:
    def __init__(self):
        pass

    def get_choice(self, settings: dict) -> int:
        """Returns the current value for this setting"""
        # TO DO: implement logic to retrieve the choice from the settings dictionary
        return 0  # default value

    def set_choice(self, settings: dict, value: int):
        """Sets the given value into the settings object using this definition as a key"""
        # TO DO: implement logic to store the value in the settings dictionary
        pass

    def get_display_choice(self, value: int, settings: dict) -> str:
        """Returns the display string for the given enum value"""
        # TO DO: implement logic to retrieve the display string based on the value and settings
        return ""  # default value

    def get_display_choices(self, settings: dict) -> list[str]:
        """Gets the list of choices as strings based on the current settings"""
        # TO DO: implement logic to retrieve the list of choices from the settings dictionary
        return []  # default value
```

Note that I've left some parts blank (`TO DO`) since they require specific implementation depending on your use case.