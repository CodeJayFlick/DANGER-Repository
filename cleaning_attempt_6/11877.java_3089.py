class EnumDBAdapterNoTable:
    def __init__(self):
        pass

    def create_record(self, name: str, comments: str, category_id: int, size: int,
                      source_archive_id: int, source_data_type_id: int, last_change_time: int) -> None:
        raise Exception("Not allowed to update version prior to existence of Enumeration Data Types table.")

    def get_record(self, enum_id: int) -> dict or None:
        return {}

    def get_records(self) -> list or None:
        return []

    def update_record(self, record: dict, set_last_change_time: bool = False) -> None:
        raise Exception()

    def remove_record(self, enum_id: int) -> bool:
        return False

    def delete_table(self):
        pass

    def get_record_ids_in_category(self, category_id: int) -> list or tuple:
        return []

    def get_record_ids_for_source_archive(self, archive_id: int) -> list or tuple:
        return []

    def get_record_with_ids(self, source_id: str, data_type_id: str) -> dict or None:
        return {}
