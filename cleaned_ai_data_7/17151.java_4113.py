class IStorageGroupMNode:
    def __init__(self):
        pass

    def get_data_ttl(self) -> int:
        raise NotImplementedError("Must be implemented by subclass")

    def set_data_ttl(self, data_ttl: int) -> None:
        raise NotImplementedError("Must be implemented by subclass")
