Here's a translation of the Java interface `IChunkMetadata` into Python:

```Python
from abc import ABCMeta, abstractmethod
import io
import statistics

class IChunkMetadata(metaclass=ABCMeta):
    @abstractmethod
    def get_statistics(self) -> 'statistics.Statistics[Serializable]':
        pass

    @property
    @abstractmethod
    def is_modified(self) -> bool:
        pass

    @is_modified.setter
    @abstractmethod
    def is_modified(self, modified: bool):
        pass

    @property
    @abstractmethod
    def is_seq(self) -> bool:
        pass

    @is_seq.setter
    @abstractmethod
    def is_seq(self, seq: bool):
        pass

    @property
    @abstractmethod
    def version(self) -> int:
        pass

    @version.setter
    @abstractmethod
    def version(self, version: int):
        pass

    @property
    @abstractmethod
    def offset_of_chunk_header(self) -> int:
        pass

    @property
    @abstractmethod
    def start_time(self) -> int:
        pass

    @property
    @abstractmethod
    def end_time(self) -> int:
        pass

    @property
    @abstractmethod
    def is_from_old_ts_file(self) -> bool:
        pass

    @abstractmethod
    def get_chunk_loader(self) -> 'IChunkLoader':
        pass

    @property
    @abstractmethod
    def need_set_chunk_loader(self) -> bool:
        pass

    @need_set_chunk_loader.setter
    @abstractmethod
    def set_chunk_loader(self, chunk_loader: 'IChunkLoader'):
        pass

    @property
    @abstractmethod
    def file_path(self) -> str:
        pass

    @file_path.setter
    @abstractmethod
    def set_file_path(self, file_path: str):
        pass

    @property
    @abstractmethod
    def closed(self) -> bool:
        pass

    @closed.setter
    @abstractmethod
    def set_closed(self, closed: bool):
        pass

    @property
    @abstractmethod
    def data_type(self) -> 'TSDataType':
        pass

    @property
    @abstractmethod
    def measurement_uid(self) -> str:
        pass

    @abstractmethod
    def insert_into_sorted_deletions(self, start_time: int, end_time: int):
        pass

    @abstractmethod
    def get_delete_interval_list(self) -> list['TimeRange']:
        pass

    @abstractmethod
    def serialize_to(self, output_stream: io.IOBase, serialize_statistic: bool) -> None:
        pass

    @property
    @abstractmethod
    def mask(self) -> int:
        pass

    @property
    @abstractmethod
    def is_time_column(self) -> bool:
        pass

    @property
    @abstractmethod
    def is_value_column(self) -> bool:
        pass
```

Please note that Python does not have direct equivalent of Java's `interface` keyword. Instead, we use abstract base classes (ABCs) to define an interface-like behavior in Python.