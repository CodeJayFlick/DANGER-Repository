import io
from abc import ABC, abstractmethod


class RemoteBufferFileHandle(ABC):
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
    def get_data_buffer(self, index: int) -> io.IOError:
        pass

    @abstractmethod
    def put_data_buffer(self, buf: object, index: int) -> io.IOError:
        pass

    @abstractmethod
    def dispose(self) -> None:
        pass

    @abstractmethod
    def get_input_block_stream(self) -> io.IOError:
        pass

    @abstractmethod
    def get_output_block_stream(self, block_count: int) -> io.IOError:
        pass

    @abstractmethod
    def get_input_block_stream_handle(self) -> object:
        pass

    @abstractmethod
    def get_output_block_stream_handle(self, block_count: int) -> object:
        pass


class DataBuffer(io.IOError):
    # Implement the necessary methods here.
    pass


class InputBlockStream(io.IOError):
    # Implement the necessary methods here.
    pass


class OutputBlockStream(io.IOError):
    # Implement the necessary methods here.
    pass
