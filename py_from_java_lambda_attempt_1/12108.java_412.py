Here is the translation of the Java code to Python:
```
class VariableStorageDBAdapterNoTable:
    def __init__(self):
        pass

    def get_next_storage_id(self):
        raise NotImplementedError()

    def find_record_key(self, hash: int) -> int:
        return -1

    def delete_record(self, key: int):
        raise NotImplementedError()

    def get_record(self, key: int) -> dict:
        return {}

    def update_record(self, record: dict):
        raise NotImplementedError()

    def get_records(self) -> list:
        return []

    def get_record_count(self) -> int:
        return 0
```
Note that I've used the `NotImplementedError` exception to indicate where the Java code was throwing an unsupported operation exception. In Python, we don't have a direct equivalent of this concept, so I've used the `raise NotImplementedError()` statement instead.

Also, in Python, dictionaries are often used as a simple way to represent data structures like maps or hash tables. So, I've replaced the `DBRecord` class with a dictionary return type for some methods.