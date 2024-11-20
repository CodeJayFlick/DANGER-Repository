class DebugHostField:
    def __init__(self):
        pass

    def get_location_kind(self) -> int:
        # implement this method as needed
        return 0

    def get_offset(self) -> int:
        # implement this method as needed
        return 0

    def get_location(self) -> 'LOCATION':
        # implement this method as needed
        from . import LOCATION
        return LOCATION()

    def get_value(self) -> object:
        # implement this method as needed
        return None
