Here is the translation of the given Java enum class into Python:

```Python
from enum import Enum

class PatternMatchType(Enum):
    TRUE_POSITIVE = "A match at the start of known function"
    POSSIBLE_START_CODE = "A match within defined code that could be a function start"
    FP_WRONG_FLOW = "A match that can't be a function start due to the wrong incoming flow"
    FP_MISALIGNED = "A match that can't be a function start because it occurs within a defined instruction"
    POSSIBLE_START_UNDEFINED = "A match within undefined bytes that could be a function start"
    FP_DATA = "A match within defined data"
    CONTEXT_CONFLICT = "A match with a context register conflict"
    PRE_PATTERN_HIT = "A match of a pre-pattern without a post-pattern"
```

Note: Python does not have an exact equivalent to Java's enum. The above code uses the `Enum` class from Python's built-in `enum` module, which provides similar functionality but is more flexible and powerful than Java's enum type.