Here is the translation of the Java code into Python:

```Python
class WindowImpl:
    def __init__(self, list, begin, size):
        self.size = size
        self.data_type = list.get_data_type()
        self.timestamps = [list.get_time_by_index(begin + i) for i in range(size)]
        
        if self.data_type == 'INT32':
            self.int_values = [list.get_int_by_index(begin + i) for i in range(size)]
        elif self.data_type == 'INT64':
            self.long_values = [list.get_long_by_index(begin + i) for i in range(size)]
        elif self.data_type == 'FLOAT':
            self.float_values = [list.get_float_by_index(begin + i) for i in range(size)]
        elif self.data_type == 'DOUBLE':
            self.double_values = [list.get_double_by_index(begin + i) for i in range(size)]
        elif self.data_type == 'BOOLEAN':
            self.boolean_values = [list.get_boolean_by_index(begin + i) for i in range(size)]
        elif self.data_type == 'TEXT':
            self.binary_values = [list.get_binary_by_index(begin + i) for i in range(size)]

    def get_size(self):
        return self.size

    def get_data_type(self):
        return self.data_type

    def get_time(self, index):
        return self.timestamps[index]

    def get_int(self, index):
        if self.data_type == 'INT32':
            return self.int_values[index]
        else:
            raise ValueError('Unsupported data type')

    def get_long(self, index):
        if self.data_type == 'INT64':
            return self.long_values[index]
        else:
            raise ValueError('Unsupported data type')

    def get_float(self, index):
        if self.data_type == 'FLOAT':
            return self.float_values[index]
        else:
            raise ValueError('Unsupported data type')

    def get_double(self, index):
        if self.data_type == 'DOUBLE':
            return self.double_values[index]
        else:
            raise ValueError('Unsupported data type')

    def get_boolean(self, index):
        if self.data_type == 'BOOLEAN':
            return self.boolean_values[index]
        else:
            raise ValueError('Unsupported data type')

    def get_binary(self, index):
        if self.data_type == 'TEXT':
            return self.binary_values[index]
        else:
            raise ValueError('Unsupported data type')
```

Note that Python does not have a direct equivalent to Java's `TSDataType` enum. Instead, we use strings to represent the different types of data (`'INT32'`, `'INT64'`, etc.).