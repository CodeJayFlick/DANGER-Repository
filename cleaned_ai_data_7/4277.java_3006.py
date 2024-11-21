class SearchAddressIterator:
    def __init__(self):
        pass

    def has_next(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def next(self) -> 'Address':
        raise NotImplementedError("Subclasses must implement this method")


class Address:
    def __init__(self, value: str):
        self.value = value
