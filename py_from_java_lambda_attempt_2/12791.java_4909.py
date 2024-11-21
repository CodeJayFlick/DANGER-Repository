Here is the translation of the Java code to Python:
```
class LinearDataAddressCorrelation:
    def __init__(self, source_data: 'Data', destination_data: 'Data'):
        self.source_data = source_data
        self.destination_data = destination_data

    def get_correlated_destination_range(self, source_address: int, monitor=None) -> tuple:
        offset = source_address.get_offset()
        base = self.source_data.address.offset
        delta = offset - base
        address = self.destination_data.address + delta
        return (address, address)

    def get_name(self):
        return "LinearDataAddressCorrelation"
```
Note that I've used type hints for the `__init__` method and the `get_correlated_destination_range` method to indicate their expected input types. In Python, these are not enforced at runtime, but they can be useful for documentation purposes.

I also replaced the Java-style constructor with a Python-style initializer (`__init__`) that sets instance variables using keyword arguments.

The rest of the code is similar in both languages: we have two methods, `get_correlated_destination_range` and `get_name`, which are implemented similarly to their Java counterparts.