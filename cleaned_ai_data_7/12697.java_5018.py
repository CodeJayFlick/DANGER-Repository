class ShiftedReference:
    def __init__(self):
        pass

    def get_shift(self) -> int:
        """Returns the left shift amount."""
        raise NotImplementedError("Subclasses must implement this method")

    def get_value(self) -> int:
        """Returns the base value."""
        raise NotImplementedError("Subclasses must implement this method")
