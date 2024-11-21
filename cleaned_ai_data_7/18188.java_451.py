from abc import ABC, abstractmethod
import statistics  # Assuming you have a Statistics class in your project
from typing import List

class ITimeSeriesMetadata(ABC):
    @abstractmethod
    def get_statistics(self) -> 'Statistics':
        pass

    @property
    def is_modified(self) -> bool:
        raise NotImplementedError("Method not implemented")

    @is_modified.setter
    def set_modified(self, modified: bool):
        raise NotImplementedError("Method not implemented")

    @property
    def is_seq(self) -> bool:
        raise NotImplementedError("Method not implemented")

    @is_seq.setter
    def set_seq(self, seq: bool):
        raise NotImplementedError("Method not implemented")

    @abstractmethod
    def load_chunk_metadata_list(self) -> List['ChunkMetadata']:
        pass

    @property
    def chunk_metadata_list(self) -> List['ChunkMetadata']:
        raise NotImplementedError("Method not implemented")

    @chunk_metadata_list.setter
    def set_chunk_metadata_loader(self, loader: 'IChunkMetadataLoader'):
        raise NotImplementedError("Method not implemented")
