class OldVariableStorageDBAdapterV0V1:
    VARIABLE_STORAGE_TABLE_NAME = "VariableStorage"
    VARIABLE_STORAGE_SCHEMA = {
        'Key': {'type': int},
        'Address': {'type': int, 'length': 8},
        'NamespaceID': {'type': int, 'length': 4},
        'SymCount': {'type': int}
    }

    STORAGE_ADDR_COL = 0
    NAMESPACE_ID_COL = 1
    SYMBOL_COUNT_COL = 2

    def __init__(self):
        pass

class DBRecord:
    def __init__(self, data):
        self.data = data

class Table:
    def __init__(self, name):
        self.name = name
        self.records = {}

    def get_record(self, key):
        return self.records.get(key)

    def find_records(self, namespace_id, col):
        records = []
        for record in self.records.values():
            if record[col] == namespace_id:
                records.append(record)
        return records

class DBHandle:
    def __init__(self):
        pass

    def get_table(self, name):
        # Assuming the table exists
        return Table(name)

# Usage example:

db_handle = DBHandle()
adapter = OldVariableStorageDBAdapterV0V1()

try:
    adapter.variable_storage_table = db_handle.get_table(adapter.VARIABLE_STORAGE_TABLE_NAME)
except Exception as e:
    print(f"Error: {e}")

def get_record(key):
    return adapter.variable_storage_table.get_record(key)

def get_records_for_namespace(namespace_id):
    keys = [record[adapter.NAMESPACE_ID_COL] for record in adapter.variable_storage_table.records.values() if record[adapter.NAMESPACE_ID_COL] == namespace_id]
    records = []
    for key in keys:
        records.append(get_record(key))
    return records
