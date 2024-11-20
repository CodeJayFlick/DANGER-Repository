Here is the translation of the Java code to Python:
```
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
```
Note that I've used the `@property` decorator to create read-only properties for the `flavor` and `type_name` attributes. In Java, these would be getter methods, but in Python, we can use properties instead.

Also, I haven't implemented the `DataFlavor` class as it's not a built-in Python class. You may need to implement it or use an existing library that provides similar functionality.