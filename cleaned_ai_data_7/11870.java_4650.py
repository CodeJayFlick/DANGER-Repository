class DataTypeDB:
    def __init__(self, data_mgr: 'DataTypeManager', cache: dict, record: DBRecord):
        self.data_mgr = data_mgr
        self.record = record
        self.lock = data_mgr.lock
        self.name = None
        self.category = None

    def refresh_name(self) -> str:
        return self.do_get_name()

    @abstractmethod
    def do_get_name(self) -> str:
        pass

    # ... (other methods)

class DBRecord:
    def __init__(self, key: int):
        self.key = key

class UniversalID:
    def __init__(self, id: int):
        self.id = id

# ... other classes and functions
