class BooleanSettingsDefinition:
    def __init__(self):
        pass

    def get_value(self, settings: dict) -> bool:
        """gets the value for this SettingsDefinition given a Settings object."""
        raise NotImplementedError("Subclasses must implement this method")

    def set_value(self, settings: dict, value: bool) -> None:
        """Sets the given value into the given settings object using this settingsDefinition as the key."""
        raise NotImplementedError("Subclasses must implement this method")
