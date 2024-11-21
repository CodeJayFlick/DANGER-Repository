Here is the translation of the given Java enum code into a Python equivalent:

```
from enum import Enum

class SpaceType(Enum):
    CONSTANT = "IPTR_CONSTANT"  # Special space to represent constants
    PROCESSOR = "IPTR_PROCESSOR"  # Normal spaces modelled by processor
    SPACEBASE = "IPTR_SPACEBASE"  # addresses=offsets off of base register
    INTERNAL = "IPTR_INTERNAL"   # Internally managed temporary space
    FSPEC = "IPTR_FSPEC"         # Special internal
    IOP = "IPTR_IOP"
```

This Python code defines a class `SpaceType` that inherits from the built-in `Enum` class. The enum values are defined as string constants, which is equivalent to how they were represented in Java.