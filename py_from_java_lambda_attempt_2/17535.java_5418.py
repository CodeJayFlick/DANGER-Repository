Here is a translation of the Java code into equivalent Python:

```Python
class UDTFMath:
    def __init__(self):
        self.transformer = None
        self.data_type = None

    def validate(self, parameters):
        if not isinstance(parameters, dict) or 'data_type' not in parameters:
            raise ValueError('Invalid input series data type')
        allowed_types = [int, float]
        if parameters['data_type'] not in allowed_types:
            raise ValueError(f"Allowed types are {allowed_types}")

    def before_start(self, parameters):
        self.data_type = parameters.get('data_type', None)
        set_transformer()

    def transform(self, row):
        time = row[0]['time']
        if self.data_type == int:
            return {'time': time, 'value': self.transformer.transform(row[0]['int_value'])}
        elif self.data_type == float:
            return {'time': time, 'value': self.transformer.transform(row[0]['float_value'])}
        else:  # assume data type is double
            return {'time': time, 'value': self.transformer.transform(row[0]['double_value'])}

    def set_transformer(self):
        pass

class Transformer:
    def transform(self, operand):
        raise NotImplementedError('Subclasses must implement this method')

def main():
    udtf = UDTFMath()
    # usage example
    row1 = {'time': 12345, 'int_value': 10}
    row2 = {'time': 67890, 'float_value': 3.14}

    for row in [row1, row2]:
        result = udtf.transform(row)
        print(result)

if __name__ == "__main__":
    main()
```

This Python code is a direct translation of the Java code provided. Note that I have used dictionaries to represent rows and series data types are not explicitly checked for in this implementation as they were in the original Java code.