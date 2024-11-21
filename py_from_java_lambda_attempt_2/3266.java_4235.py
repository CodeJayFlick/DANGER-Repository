Here is the translation of the Java interface `DataLocationListContext` into a Python class:

```Python
class DataLocationListContext:
    def __init__(self):
        pass

    def get_count(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")

    def get_data_location_list(self) -> list:
        raise NotImplementedError("Subclasses must implement this method")

    def get_data_location_list(self, filter: callable = None) -> list:
        if filter is None:
            return self.get_data_location_list()
        else:
            return [location for location in self.get_data_location_list() if filter(location)]

    def get_program(self) -> object:
        raise NotImplementedError("Subclasses must implement this method")
```

This Python class defines the same methods as the Java interface, but with some differences:

- The `get_count` and `get_data_location_list` methods are marked as abstract by raising a `NotImplementedError`, which means that any subclass of `DataLocationListContext` will have to provide an implementation for these methods.
- The `get_data_location_list` method now takes an optional filter parameter, which is used to filter the list of locations. If no filter is provided (i.e., it's `None`), then all elements are returned.
- The return type of each method has been changed from Java-style (`int`, `List<ProgramLocation>`) to Python-style (`int`, `list`).