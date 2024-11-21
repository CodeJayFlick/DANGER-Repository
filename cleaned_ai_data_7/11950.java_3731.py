class FunctionTagMappingAdapterNoTable:
    def __init__(self):
        pass

    # PUBLIC METHODS

    def get_record(self, function_id: int, tag_id: int) -> None:
        return None

    def create_function_tag_record(self, function_id: int, tag_id: int) -> None:
        raise NotImplementedError("create record not supported")

    def remove_function_tag_record(self, function_id: int, tag_id: int) -> None:
        raise NotImplementedError("remove record not supported")

    def remove_function_tag_record_by_tag_id(self, tag_id: int) -> None:
        raise NotImplementedError("remove record not supported")

    def get_records_by_function_id(self, function_id: int) -> list[None]:
        return []

    def is_tag_assigned(self, id: int) -> bool:
        return False

    def get_all_records(self) -> list[None]:
        return []
