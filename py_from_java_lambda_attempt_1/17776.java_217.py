Here is the translation of the Java enum to a Python enumeration:

```
from enum import Enum

class CompactionOverlapType(Enum):
    FILE_NO_OVERLAP = 1
    FILE_OVERLAP_CHUNK_NO_OVERLAP = 2
    CHUNK_OVERLAP_PAGE_NO_OVERLAP = 3
    PAGE_OVERLAP = 4
```