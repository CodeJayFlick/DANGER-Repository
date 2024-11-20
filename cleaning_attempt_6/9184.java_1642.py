from abc import ABCMeta, abstractmethod


class ManagedBufferFile(metaclass=ABCMeta):
    @abstractmethod
    def get_next_change_data_file(self, get_first: bool) -> 'ManagedBufferFile':
        pass

    @abstractmethod
    def get_save_change_data_file(self) -> 'ManagedBufferFile':
        pass

    @abstractmethod
    def get_forward_mod_map_data(self, old_version: int) -> bytes:
        pass

    @abstractmethod
    def get_save_file(self) -> 'ManagedBufferFile':
        pass

    @abstractmethod
    def save_completed(self, commit: bool):
        pass

    @abstractmethod
    def can_save(self) -> bool:
        pass

    @abstractmethod
    def set_version_comment(self, comment: str):
        pass

    @abstractmethod
    def get_checkin_id(self) -> int:
        pass


class BufferFile(metaclass=ABCMeta):
    @abstractmethod
    pass  # You can add methods here if you want to keep the interface separate from ManagedBufferFile.
