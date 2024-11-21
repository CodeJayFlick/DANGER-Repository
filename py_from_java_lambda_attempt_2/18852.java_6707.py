Here is the translation of the given Java code into equivalent Python:

```Python
from abc import ABC, abstractmethod
import typing as t

class DeltaLakeTable(ABC):
    @abstractmethod
    def get_metadata_location_history(self) -> t.List[str]:
        pass

    @abstractmethod
    def get_checkpoint_location_history(self) -> t.List[str]:
        pass

    @abstractmethod
    def get_last_checkpoint(self) -> str:
        pass
```

Note that Python does not have a direct equivalent to Java's `@Value.Immutable` or `@JsonSerialize/@JsonDeserialize`, as these are Jackson annotations for serializing and deserializing objects in JSON format, which is specific to the Jackson library used in Java.