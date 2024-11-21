Here is the translation of the Java interface `IKeyEnumerator` into a Python class:

```Python
from enum import Enum

class VTIndices(Enum):
    RESET = 0
    GET_NEXT = 1


class IKeyEnumerator:
    IID_IKEY_ENUMERATOR = "345FA92E-5E00-4319-9CAE-971F7601CDCF"

    def __init__(self):
        pass

    def Reset(self) -> int:
        # Implement the logic for Reset method
        return 0

    def GetNext(self, key: str, value: object, metadata: object) -> int:
        # Implement the logic for GetNext method
        return 0


if __name__ == "__main__":
    ike = IKeyEnumerator()
    print(ike.Reset())
    print(ike.GetNext("key", None, None))
```

Please note that Python does not have direct equivalent of Java's `interface` or `enum`. In the above code, we are using a class to represent an interface and enum is represented by Python's built-in `Enum` type.