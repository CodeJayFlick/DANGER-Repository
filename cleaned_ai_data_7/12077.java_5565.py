class EquateDBAdapter:
    EQUATES_TABLE_NAME = "Equates"
    NAME_COL = 0
    VALUE_COL = 1

    def __init__(self):
        pass

    @staticmethod
    def get_adapter(db_handle, open_mode, monitor=None):
        if open_mode == 'CREATE':
            return EquateDBAdapterV0(db_handle, True)
        else:
            return EquateDBAdapterV0(db_handle, False)

class DBRecord:
    def __init__(self, name, value):
        self.name = name
        self.value = value

class RecordIterator:
    pass  # This class is not implemented in the given Java code.

def get_record_key(self, name: str) -> int:
    raise NotImplementedError("Method must be implemented by subclass")

def get_record(self, key: int) -> DBRecord:
    raise NotImplementedError("Method must be implemented by subclass")

def remove_record(self, key: int):
    raise NotImplementedError("Method must be implemented by subclass")

def update_record(self, record: DBRecord):
    raise NotImplementedError("Method must be implemented by subclass")

def create_equate(self, name: str, value: int) -> DBRecord:
    raise NotImplementedError("Method must be implemented by subclass")

def get_records(self) -> RecordIterator:
    raise NotImplementedError("Method must be implemented by subclass")

def has_record(self, name: str) -> bool:
    raise NotImplementedError("Method must be implemented by subclass")
