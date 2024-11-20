class FunctionParameterAdapterNoTable:
    def __init__(self):
        pass  # no table required

    def create_record(self, data_type_id: int, parent_id: int, ordinal: int, name: str, comment: str, dt_length: int) -> None:
        return None

    def get_record(self, parameter_id: int) -> None:
        return None

    def get_records(self) -> 'RecordIterator':
        from ghidra.util.recorditerator import EmptyRecordIterator
        return EmptyRecordIterator()

    def update_record(self, record: object) -> None:
        raise UnsupportedOperationException()  # unsupported operation

    def remove_record(self, parameter_id: int) -> bool:
        return False

    def delete_table(self):
        pass  # do nothing

class Field:
    @staticmethod
    def EMPTY_ARRAY():
        from ghidra.util.array import ArrayIntField
        return ArrayIntField([])

# usage example
adapter = FunctionParameterAdapterNoTable()
print(adapter.create_record(1, 2, 3, 'name', 'comment', 4))  # returns None
