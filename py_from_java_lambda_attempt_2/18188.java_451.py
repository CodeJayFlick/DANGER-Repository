Here is the translation of the Java interface `ITimeSeriesMetadata` to a Python class:

```python
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
```

Note that I've used Python's `ABC` (Abstract Base Class) and `abstractmethod` to define the abstract methods. The rest of the code is just a translation from Java interface syntax to Python class syntax.

Also, please note that you'll need to implement these abstract methods in your concrete subclass.