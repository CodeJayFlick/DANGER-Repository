class CommentHistoryAdapterNoTable:
    def create_record(self, addr: int, comment_type: bytes, pos1: int, pos2: int, data: str, date: int) -> None:
        raise NotImplementedError()

    def get_records_by_address(self, addr: 'Address') -> list['DBRecord']:
        return []

    def get_all_records(self) -> list['DBRecord']:
        return []

    def update_record(self, rec: 'DBRecord') -> None:
        raise NotImplementedError()

    def delete_records(self, start: 'Address', end: 'Address') -> None:
        raise NotImplementedError()

    def get_record_count(self) -> int:
        return 0


class Address:
    pass

class DBRecord:
    pass
