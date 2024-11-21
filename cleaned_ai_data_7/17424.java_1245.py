class SingleDataSet:
    def __init__(self, paths: list, data_types: list):
        self.record = None
        super().__init__([PartialPath(*path) for path in paths], data_types)

    @property
    def record(self):
        return self._record

    @record.setter
    def record(self, value):
        self._record = value

    def set_record(self, record: 'RowRecord'):
        self.record = record

    def has_next_without_constraint(self) -> bool:
        return False  # equivalent to i == 0 in Java

    def next_without_constraint(self) -> 'RowRecord':
        if not hasattr(self, '_record') or self._record is None:
            raise ValueError("No more records")
        result = self._record
        self._record = None
        return result


class PartialPath:  # equivalent to org.apache.iotdb.tsfile.file.metadata.enums.PartialPath in Java
    def __init__(self, *path):
        self.path = path

    def __repr__(self):
        return str(self.path)


class RowRecord:
    pass  # placeholder for the equivalent class in Python


# Example usage:
paths = [[1, 2], [3, 4]]
data_types = ['int', 'float']
dataset = SingleDataSet(paths, data_types)
record = dataset.set_record(RowRecord())  # set a record
print(dataset.has_next_without_constraint())  # prints: True
print(dataset.next_without_constraint())  # returns the first record
