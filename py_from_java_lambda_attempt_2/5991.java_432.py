Here's a translation of your Java code into equivalent Python:

```Python
class AddressSizeProjectDataColumn:
    def __init__(self):
        pass

    def get_column_name(self):
        return "Address Size"

    def get_value(self, info, settings, data, services):
        size_string = info.get_metadata_value("Address Size")
        if size_string is None:
            return None
        try:
            return int(size_string)
        except ValueError:
            return None

    def get_column_preferred_width(self):
        return 60

    def is_default_column(self):
        return True

    def get_priority(self):
        return 3


# Example usage:

class DomainFileInfo:
    def __init__(self, metadata_value=None):
        self.metadata_value = metadata_value

    def get_metadata_value(self, key):
        if key == "Address Size":
            return self.metadata_value
        else:
            return None


class ServiceProvider:
    pass


def main():
    info = DomainFileInfo(metadata_value="4")
    settings = None  # You might need to implement this class or use a different approach.
    data = None  # Same as above.
    services = ServiceProvider()

    column = AddressSizeProjectDataColumn()
    print(column.get_column_name())  # Output: "Address Size"
    value = column.get_value(info, settings, data, services)
    if value is not None:
        print(value)  # Output: 4
    else:
        print("Value is null or could not be parsed.")

if __name__ == "__main__":
    main()
```

This Python code does essentially the same thing as your Java code. It defines a class `AddressSizeProjectDataColumn` with methods that mirror those in your original code, and then demonstrates how to use these methods by creating instances of other classes (`DomainFileInfo`, `ServiceProvider`) and calling the column's methods on them.

Please note that this is not an exact translation because Python does not have direct equivalents for Java concepts like packages or static imports.