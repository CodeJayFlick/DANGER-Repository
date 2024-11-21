Here is the translation of the Java code to Python:
```
from collections import OrderedDict

class FixedSizeMRUCachingFactory:
    def __init__(self, factory, size):
        self.delegate = factory
        self.cache = OrderedDict(maxlen=size)

    def get(self, key):
        value = self.cache.get(key)
        if value is not None:
            return value

        value = self.delegate.get(key)
        self.cache[key] = value  # equivalent to put in Java
        return value
```
Note that I used the `OrderedDict` class from the Python standard library, which provides a dictionary-like data structure with an ordering (i.e., it remembers the order of items inserted). This is similar to the LRUMap class in Java.