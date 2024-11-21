import io


class DBFieldIterator:
    def __init__(self):
        pass

    def has_next(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def has_previous(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def next(self) -> object:
        raise NotImplementedError("Subclasses must implement this method")

    def previous(self) -> object:
        raise NotImplementedError("Subclasses must implement this method")

    def delete(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")
