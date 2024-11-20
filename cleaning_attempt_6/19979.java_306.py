class BidiMap:
    def __init__(self):
        pass  # No equivalent in Python; we'll define methods instead

    def get_reverse_view(self) -> 'BidiMap':
        raise NotImplementedError("Subclasses must implement this method")

    def get_key(self, value: object) -> object:
        raise NotImplementedError("Subclasses must implement this method")

    def get_value(self, key: object) -> object:
        raise NotImplementedError("Subclasses must implement this method")

    def values_set(self) -> set:
        raise NotImplementedError("Subclasses must implement this method")
