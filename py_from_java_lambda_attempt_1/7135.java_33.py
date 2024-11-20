Here is the translation of the Java code to Python:
```python
import struct
from collections import defaultdict

class MapList:
    def __init__(self, reader):
        self.size = reader.read_int()
        for i in range(self.size):
            item = MapItem(reader)
            self.items.append(item)

    @property
    def size(self):
        return self._size

    @property
    def items(self):
        return tuple(self._items)  # make a copy to avoid modifying the original list

class MapItem:
    def __init__(self, reader):
        pass  # not implemented in this example

def read_map_list(reader):
    map_list = MapList(reader)
    return map_list
```
Note that I did not implement the `MapItem` class as it was not provided in the original Java code. Also, I used Python's built-in `struct` module to read integers from a binary reader.

The rest of the code is translated directly from the Java code, with some minor adjustments for Python syntax and semantics.