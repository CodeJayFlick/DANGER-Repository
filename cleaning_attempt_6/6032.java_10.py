class MyTestMemoryBlock:
    def __init__(self, start: 'Address', end: 'Address'):
        self.start = start
        self.end = end

    def get_permissions(self):
        raise NotImplementedError()

    def get_data(self) -> bytes:
        raise NotImplementedError()

    def contains(self, addr: 'Address') -> bool:
        raise NotImplementedError()

    @property
    def start_address(self) -> 'Address':
        return self.start

    @property
    def end_address(self) -> 'Address':
        return self.end

    def get_size(self):
        raise NotImplementedError()

    def get_name(self) -> str:
        raise NotImplementedError()

    def set_name(self, name: str):
        raise NotImplementedError()

    def get_comment(self) -> str:
        raise NotImplementedError()

    def set_comment(self, comment: str):
        raise NotImplementedError()

    def is_read_only(self) -> bool:
        raise NotImplementedError()

    def set_readable(self, r: bool):
        raise NotImplementedError()

    def is_writeable(self) -> bool:
        raise NotImplementedError()

    def set_writable(self, w: bool):
        raise NotImplementedError()

    def is_executable(self) -> bool:
        raise NotImplementedError()

    def set_executable(self, e: bool):
        raise NotImplementedError()

    def set_permissions(self, read: bool, write: bool, execute: bool):
        raise NotImplementedError()

    @property
    def volatile_(self) -> bool:
        return False

    def get_source_name(self) -> str:
        raise NotImplementedError()

    def set_source_name(self, source_name: str):
        raise NotImplementedError()

    def get_byte(self, addr: 'Address') -> int:
        raise NotImplementedError()

    def put_bytes(self, addr: 'Address', b: bytes) -> None:
        raise NotImplementedError()

    @property
    def type_(self) -> str:
        return "DEFAULT"

    @property
    def is_overlay(self) -> bool:
        return False

    def compare_to(self, block: object) -> int:
        raise NotImplementedError()
