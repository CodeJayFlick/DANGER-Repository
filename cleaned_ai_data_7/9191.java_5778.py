import io
from abc import ABC, abstractmethod


class RemoteManagedBufferFileHandle(ABC):
    @abstractmethod
    def is_read_only(self) -> bool:
        pass

    @abstractmethod
    def set_read_only(self) -> None:
        pass

    @abstractmethod
    def get_parameter(self, name: str) -> int:
        pass

    @abstractmethod
    def set_parameter(self, name: str, value: int) -> None:
        pass

    @abstractmethod
    def clear_parameters(self) -> None:
        pass

    @abstractmethod
    def get_parameter_names(self) -> list[str]:
        pass

    @abstractmethod
    def get_buffer_size(self) -> int:
        pass

    @abstractmethod
    def get_index_count(self) -> int:
        pass

    @abstractmethod
    def get_free_indexes(self) -> list[int]:
        pass

    @abstractmethod
    def set_free_indexes(self, indexes: list[int]) -> None:
        pass

    @abstractmethod
    def close(self) -> None:
        pass

    @abstractmethod
    def delete(self) -> bool:
        pass

    @abstractmethod
    def get_data_buffer(self, index: int) -> any:
        pass

    @abstractmethod
    def put_data_buffer(self, buf: any, index: int) -> None:
        pass

    @abstractmethod
    def dispose(self) -> None:
        pass

    @abstractmethod
    def get_input_block_stream(self) -> io.IOBase:
        pass

    @abstractmethod
    def get_output_block_stream(self, block_count: int) -> any:
        pass

    @abstractmethod
    def get_input_block_stream_handle(self) -> any:
        pass

    @abstractmethod
    def get_output_block_stream_handle(self, block_count: int) -> any:
        pass


class ManagedBufferFileHandle(RemoteManagedBufferFileHandle):
    # Implement the abstract methods here
