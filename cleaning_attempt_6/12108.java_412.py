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
