class FunctionTagAdapter:
    TABLE_NAME = "Function Tags"
    CURRENT_VERSION = 0
    NAME_COL = 0
    COMMENT_COL = 1

    def __init__(self, handle):
        pass

    @staticmethod
    def get_adapter(handle, open_mode, monitor=None):
        if open_mode == 'CREATE':
            return FunctionTagAdapterV0(handle, True)
        try:
            return FunctionTagAdapterV0(handle, False)
        except VersionException as e:
            if not e.is_upgradable() or open_mode == 'UPDATE':
                raise e
            adapter = find_read_only_adapter(handle)
            if open_mode == 'UPGRADE':
                adapter = upgrade(handle, adapter, monitor)
            return adapter

    @staticmethod
    def find_read_only_adapter(handle):
        return None

    @staticmethod
    def upgrade(handle, old_adapter, monitor=None):
        return FunctionTagAdapterV0(handle, True)

    def get_records(self) -> list:
        pass  # implement this method in the subclass

    def get_record(self, tag: str) -> dict or None:
        pass  # implement this method in the subclass

    def get_record_by_id(self, id: int) -> dict or None:
        pass  # implement this method in the subclass

    def create_tag_record(self, tag: str, comment: str) -> dict:
        pass  # implement this method in the subclass

    def update_record(self, record):
        pass  # implement this method in the subclass

    def remove_tag_record(self, id: int):
        pass  # implement this method in the subclass

    def get_num_tags(self) -> int:
        pass  # implement this method in the subclass


class FunctionTagAdapterV0(FunctionTagAdapter):

    def __init__(self, handle, is_upgradable=True):
        super().__init__(handle)
