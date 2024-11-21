import io

class DBLongIterator:
    def __init__(self):
        pass

    def has_next(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def has_previous(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def next(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")

    def previous(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")

    def delete(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")
