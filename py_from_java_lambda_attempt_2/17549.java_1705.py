Here is a translation of the Java code into equivalent Python:

```Python
class UDTFValueDifference:
    def __init__(self):
        self.data_type = None
        self.has_previous = False

    def before_start(self, parameters: dict, configurations: dict) -> None:
        try:
            self.data_type = parameters['data_type'][0]
            configurations['access_strategy'] = 'RowByRowAccessStrategy'
            configurations['output_data_type'] = self.data_type
        except Exception as e:
            raise MetadataException(str(e))

    def transform(self, row: dict, collector) -> None:
        if not self.has_previous:
            try:
                update_previous_value(row)
                self.has_previous = True
                return
            except UDFInputSeriesDataTypeNotValidException as e:
                raise

        do_transform(row, collector)

def update_previous_value(row):
    # Your code here to handle the previous value and row
    pass

def do_transform(row, collector):
    # Your code here for transforming the row and collecting points
    pass
```

Please note that Python does not have direct equivalent of Java's abstract classes. Also, Python is dynamically typed language so you don't need to specify data type explicitly like in Java.