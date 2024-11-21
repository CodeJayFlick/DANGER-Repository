Here is the translation of the Java code into Python:

```Python
class StringsTable:
    STRINGS_TABLE = "Strings Table"
    STRING_VALUE_COL = 0
    CACHE_SIZE = 10000

    SCHEMA = {
        'version': LibrariesTable.VERSION,
        'name': "String ID",
        'fields': [{'type': 'string', 'name': "String Value"}]
    }

    INDEXED_COLUMNS = [STRING_VALUE_COL]

    def __init__(self, handle):
        self.table = handle.get_table(self.STRINGS_TABLE)
        self.string_cache = {}

    @classmethod
    def create_table(cls, handle):
        handle.create_table(cls.STRINGS_TABLE, cls.SCHEMA, cls.INDEXED_COLUMNS)

    def obtain_string_id(self, value):
        records = self.table.find_records({'String Value': value}, self.STRING_VALUE_COL)
        if not records:
            key = next_id()
            record = {'key': key, 'value': value}
            self.table.put_record(record)
            return key
        else:
            return records[0]['key']

    def lookup_string_id(self, value):
        records = self.table.find_records({'String Value': value}, self.STRING_VALUE_COL)
        if not records:
            return None
        else:
            return records[0]['key']

    def lookup_string(self, string_id):
        if string_id in self.string_cache:
            return self.string_cache[string_id]
        try:
            record = self.table.get_record(string_id)
            value = record['String Value']
            self.string_cache[string_id] = {'value': value}
            return self.string_cache[string_id]
        except Exception as e:
            raise RuntimeError("serious delayed database access error", e)

def next_id():
    # implement your own ID generator here
    pass

# Example usage:

handle = DBHandle()  # replace with actual handle
table = StringsTable(handle)
print(table.obtain_string_id('Hello'))
```

Please note that this translation is not a direct conversion from Java to Python, but rather an interpretation of the code. Some parts may have been modified or simplified for better compatibility with Python's syntax and semantics.

Also, please replace `DBHandle` and `LibrariesTable.VERSION` with actual implementations in your Python program.