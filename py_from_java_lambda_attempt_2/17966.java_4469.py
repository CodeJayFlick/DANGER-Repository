Here is the translation of the Java code to Python:

```Python
import logging

class Adder:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.addend = 0

    def validate(self, parameters):
        if not isinstance(parameters, dict) or 'addend' not in parameters:
            raise Exception('Invalid input')
        addend_value = float(parameters.get('addend', 0))
        return True

    def before_start(self, parameters):
        self.logger.debug("Adder#beforeStart")
        self.addend = float(parameters['addend'])

    def transform(self, row):
        if any(value is None for value in row.values()):
            return
        result = sum(extract_value(row, i) for i in range(len(row)))
        yield {'time': row[0], 'value': int(result + self.addend)}

    def extract_value(self, row, index):
        data_type = type(next(iter(row)).values())[index]
        if data_type == int:
            return row[index]
        elif data_type == float:
            return row[index]
        else:
            raise Exception(f"Unsupported data type: {data_type}")

if __name__ == "__main__":
    adder = Adder()
```

Note that this Python code does not exactly translate the Java code, but it achieves similar functionality. The `transform` method now yields a dictionary for each row in the input stream, with 'time' and 'value' keys.