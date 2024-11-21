# This plugin is for testing circular dependencies.
class CircularPluginA:
    def __init__(self):
        pass  # No need for a constructor in Python.

    def get_services_provided(self) -> list:
        return [CircularServiceA]

    def get_services_required(self) -> list:
        return [CircularServiceB]
