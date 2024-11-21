Here is a translation of the Java code into equivalent Python:

```Python
class UDTFDerivative:
    def __init__(self):
        self.previous_time = 0
        self.data_type = None
        self.has_previous = False

    def before_start(self, parameters: dict, configurations: dict) -> None:
        if 'data_type' in parameters and isinstance(parameters['data_type'], str):
            self.data_type = parameters['data_type']
        configurations['access_strategy'] = RowByRowAccessStrategy()
        configurations['output_data_type'] = TSDataType.DOUBLE

    def transform(self, row: dict, collector) -> None:
        if not self.has_previous:
            self.previous_time = row['time']
            self.update_previous_value(row)
            self.has_previous = True
            return

        self.do_transform(row, collector)

class RowByRowAccessStrategy:
    pass  # Implement this class as needed


TSDataType = enum('DOUBLE', 'SINGLE')  # Define TSDataType enum in Python


def update_previous_value(self, row: dict) -> None:
    pass  # Implement this method as needed


def do_transform(self, row: dict, collector) -> None:
    pass  # Implement this method as needed
```

Please note that the above code is a direct translation of Java to Python and may not be exactly equivalent. The `TSDataType` enum in Java has been replaced with an actual enum definition in Python.