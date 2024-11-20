Here is the translation of the given Java code into equivalent Python:

```Python
from weakref import WeakValueDictionary as CACHE
import collections

class DebugHostExtensabilityInternal:
    PREFERRED_DATA_SPACES_IIDS = collections.defaultdict(lambda: None)

    @classmethod
    def instance_for(cls, data):
        return DbgModelUtil.lazy_weak_cache(CACHE, data, lambda x: cls())

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return DbgModelUtil.try_preferred_interfaces(cls.__class__, DebugHostExtensabilityInternal.PREFERRED_DATA_SPACES_IIDS, supplier)
```

Please note that Python does not have direct equivalent of Java's `ImmutableMap` and `REFIID`. The above code uses a dictionary (`PREFERRED_DATA_SPACES_IIDS`) to store the preferred data spaces.