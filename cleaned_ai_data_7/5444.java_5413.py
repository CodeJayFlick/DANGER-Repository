class Recognizer:
    def __init__(self):
        pass

    def number_of_bytes_required(self) -> int:
        """How many bytes (maximum) does this recognizer need to recognize its format?"""
        raise NotImplementedError("Subclasses must implement this method")

    def recognize(self, bytes: bytearray) -> str | None:
        """Ask the recognizer to recognize some bytes. Return a description String if recognized; otherwise, null."""
        raise NotImplementedError("Subclasses must implement this method")

    def get_priority(self) -> int:
        """Return the recognizer priority"""
        raise NotImplementedError("Subclasses must implement this method")
