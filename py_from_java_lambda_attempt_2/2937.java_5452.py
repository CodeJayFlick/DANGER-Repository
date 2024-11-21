Here is a translation of the provided Java code into equivalent Python:

```Python
class SampleSearchTableModel:
    def __init__(self, searcher):
        self.searcher = searcher

    def load(self, accumulator=None, monitor=None):
        if accumulator is None:
            accumulator = []
        self.searcher.search(accumulator, monitor)

    def create_table_column_descriptor(self):
        descriptor = {}
        descriptor['columns'] = [
            {'name': 'Address', 'column_class': MyAddressColumn},
            {'name': 'Value', 'column_class': MyValueColumn}
        ]
        return descriptor

class MyAddressColumn:
    def get_name(self):
        return "Address"

    def get_value(self, row_object, settings=None, data=None, services=None):
        return row_object['address']

class MyValueColumn:
    def get_name(self):
        return "Value"

    def get_value(self, row_object, settings=None, data=None, services=None):
        return row_object['display_value']

# Example usage
searcher = SampleSearcher()  # Implement this class according to your needs
table_model = SampleSearchTableModel(searcher)
```

Please note that the provided Java code is a part of Ghidra's API and might require additional setup or imports in Python.