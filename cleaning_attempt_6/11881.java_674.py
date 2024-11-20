class EnumValueDBAdapterNoTable:
    def __init__(self):
        pass  # no table needed

    def create_record(self, enum_id: int, name: str, value: int, comment: str) -> None:
        raise Exception("Unsupported operation")

    def get_record(self, value_id: int) -> dict or None:
        return {}

    def update_record(self, record: dict) -> None:
        raise Exception("Unsupported operation")

    def remove_record(self, value_id: int) -> None:
        raise Exception("Unsupported operation")

    def get_value_ids_in_enum(self, enum_id: int) -> list:
        return []

    def get_records(self) -> iter or None:
        return iter([])

    def delete_table(self):
        pass  # do nothing

    def translate_record(self, rec: dict) -> dict:
        raise Exception("Unsupported operation")
