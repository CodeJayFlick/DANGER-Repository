Here is the translation of the given Java code into equivalent Python:

```Python
from weakref import WeakValueDictionary as CACHE
import functools

class KeyStoreInternal:
    PREFERRED_DATA_SPACES_IIDS = {
        'IKey_Store': WrapIKeyStore,
    }

    @functools.lru_cache(maxsize=None)
    def instance_for(data):
        return DbgModelUtil.lazy_weak_cache(CACHE, data, lambda: KeyStoreImpl())

    try_preferred_interfaces = staticmethod(functools.partial(DbgModelUtil.try_preferred_interfaces, class_=KeyStoreInternal))

class WrapIKeyStore:
    pass

class REFIID:
    def __init__(self, iid):
        self.iid = iid
```

Please note that Python does not have direct equivalent of Java's `Map`, `ImmutableMap` and other data structures. We are using a dictionary (`PREFERRED_DATA_SPACES_IIDS`) to achieve the same functionality.

Also, we are using `functools.lru_cache` for memoization in the `instance_for` method which is similar to Java's lazyWeakCache() function.