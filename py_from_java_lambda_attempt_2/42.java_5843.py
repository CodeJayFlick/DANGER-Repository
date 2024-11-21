Here is the translation of the Java code to Python:

```Python
class DebuggerTrackLocationAction:
    def __init__(self):
        pass

    @staticmethod
    def builder(owner):
        builder = TrackLocationAction.builder(owner)
        builder.toolbar_group(owner.name)
        builder.perform_action_on_button_click(True)

        for spec in LocationTrackingSpec.all_specs().values():
            builder.add_state(spec.menu_name, spec.menu_icon, spec)

        return builder


class MultiStateActionBuilder:
    def __init__(self):
        pass

    @staticmethod
    def add_state(menu_name, menu_icon, state):
        # Add implementation for this method if needed
        pass

    @staticmethod
    def perform_action_on_button_click(enabled):
        # Add implementation for this method if needed
        pass

    @staticmethod
    def toolbar_group(group_name):
        # Add implementation for this method if needed
        pass


class LocationTrackingSpec:
    @staticmethod
    def all_specs():
        # Add implementation for this method if needed
        return {}

    @staticmethod
    def get_menu_icon(self):
        # Add implementation for this method if needed
        pass

    @staticmethod
    def menu_name(self):
        # Add implementation for this method if needed
        pass


class TrackLocationAction:
    @staticmethod
    def builder(owner):
        # Add implementation for this method if needed
        pass
```

Please note that the above Python code is a direct translation of the Java code and does not include any actual functionality. The methods in the classes are either empty or require additional implementation based on your specific requirements.