from typing import CompletableFuture, Any

class TargetDataType:
    pass

class DataTypeManager:
    def __init__(self):
        self.data_types = {}

    def get_data_type(self) -> Any:
        return None


class Address:
    NO_ADDRESS = object()

    def is_constant_address(self) -> bool:
        return False
