Here is the translation of the Java interface `IDataModelScriptTemplate` into a Python class:

```Python
from enum import Enum

class VTIndices(Enum):
    GET_NAME = 3
    GET_DESCRIPTION = 4
    GET_CONTENT = 5


class IDataModelScriptTemplate:
    IID_ = "1303DEC4-FA3B-4F1B-9224-B953D16BABB5"

    def __init__(self):
        pass

    def get_name(self) -> None:
        # implement GetName method
        raise NotImplementedError("Method not implemented")

    def get_description(self) -> str:
        # implement GetDescription method
        raise NotImplementedError("Method not implemented")

    def get_content(self) -> bytes:
        # implement GetContent method
        raise NotImplementedError("Method not implemented")
```

Note that the `IUnknownEx` interface is not translated as it seems to be a custom Java interface.