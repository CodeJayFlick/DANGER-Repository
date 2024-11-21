Here is the equivalent Python code:

```Python
from weakref import WeakValueDictionary as WeakMap
import collections

class DebugHostDataInternal:
    _cache = WeakMap()

    @classmethod
    def instance_for(cls, data):
        return cls._lazy_weak_cache(data)

    @classmethod
    def _lazy_weak_cache(cls, cache_key, factory):
        if cache_key not in cls._cache:
            cls._cache[cache_key] = factory()
        return cls._cache[cache_key]

    PREFERRED_DATA_SPACES_IIDS = collections.defaultdict(dict)
    PREFERRED_DATA_SPACES_IIDS[IDebugHostData.IID_IDBUG_HOST_DATA] = WrapIDebugHostData

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return cls._try_preferred_interfaces(DebugHostDataInternal.__class__, 
                                             cls.PREFERRED_DATA_SPACES_IIDS, supplier)

    @classmethod
    def _try_preferred_interfaces(cls, target_class, preferred_iids, supplier):
        # implement this method as per your requirement
        pass

```

Please note that Python does not have direct equivalent of Java's `Map` and `ImmutableMap`. We are using Python's built-in dictionary (`dict`) for the same purpose. Also, Python doesn't support static methods directly like in Java but we can achieve similar functionality by defining classmethods or instance methods with a decorator.