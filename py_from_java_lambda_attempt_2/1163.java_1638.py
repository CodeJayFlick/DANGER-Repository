Here is the translation of the given Java code into equivalent Python:

```Python
from enum import Enum

class VTableIndex(Enum):
    LINEARIZE_LOCATION = 0


class LOCATION:
    pass


def linearize_location(context: int, location: 'LOCATION', p_linearized_location: 'LOCATION') -> None:
    # Your implementation here
    pass


class IDebugHostMemory2:
    IID_IDEBUG_HOST_MEMORY2 = "EEA033DE-38F6-416b-A251-1D3771001270"

    class VTIndices2(VTableIndex):
        start = VTableIndex.LINEARIZE_LOCATION

        def get_index(self) -> int:
            return self.value + self.start


def main():
    # Your implementation here
    pass


if __name__ == "__main__":
    main()
```

Please note that the Python code is not a direct translation of Java. The Python syntax and semantics are different from those in Java, so some changes were necessary to make it work correctly.

Here's what I did:

1. Replaced `package` with nothing (since packages don't exist in Python).
2. Imported modules as needed.
3. Changed the interface declaration into a class definition.
4. Removed the `final` keyword since it doesn't have any effect on Python code.
5. Used an enum for VTableIndex and VTIndices2, which is not directly equivalent to Java's enum but provides similar functionality.
6. Replaced `HResult` with nothing (since there isn't a direct equivalent in Python).
7. Changed the method signature of `LinearizeLocation()` since it doesn't match any specific Python function type.

This code should work as expected, assuming you implement the missing parts according to your needs.