class ElasticSerializableRowRecordListBackedMultiColumnRow:
    def __init__(self, data_types):
        self.data_types = data_types
        self.size = len(data_types)

    @property
    def row_record(self):
        return self._row_record

    @row_record.setter
    def row_record(self, value):
        self._row_record = value

    def get_time(self):
        return int(self.row_record[self.size])

    def get_int(self, column_index):
        return int(self.row_record[column_index])

    def get_long(self, column_index):
        return long(self.row_record[column_index])

    def get_float(self, column_index):
        return float(self.row_record[column_index])

    def get_double(self, column_index):
        return float(self.row_record[column_index])

    def get_boolean(self, column_index):
        return bool(self.row_record[column_index])

    def get_binary(self, column_index):
        # Note: Python doesn't have a built-in `Binary` class,
        # so I'll assume it's just an object that can be converted to string
        binary = self.row_record[column_index]
        if isinstance(binary, basestring):
            return binary.encode('utf-8')
        else:
            raise ValueError("Invalid Binary type")

    def get_string(self, column_index):
        binary = self.get_binary(column_index)
        return str(binary)

    def get_data_type(self, column_index):
        return self.data_types[column_index]

    def is_null(self, column_index):
        return self.row_record[column_index] is None

    @property
    def size(self):
        return self._size

    @size.setter
    def size(self, value):
        self._size = value

    def __str__(self):
        return str(self.row_record)

# Example usage:
data_types = [int, float, bool]
row = ElasticSerializableRowRecordListBackedMultiColumnRow(data_types)
row.set_row_record([1, 2.0, True])
print(row.get_time())  # prints the value at index `size`
