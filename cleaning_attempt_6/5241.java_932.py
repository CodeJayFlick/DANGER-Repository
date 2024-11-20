class ClipboardType:
    def __init__(self, flavor: DataFlavor, type_name: str):
        self.flavor = flavor
        self.type_name = type_name

    @property
    def flavor(self) -> DataFlavor:
        return self._flavor

    @property
    def type_name(self) -> str:
        return self._type_name

    def __str__(self) -> str:
        return self.type_name


class DataFlavor:  # Note: This is not a built-in Python class, you may need to implement it or use an existing library
    pass
