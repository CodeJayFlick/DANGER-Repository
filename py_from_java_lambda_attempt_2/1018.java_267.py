Here is the equivalent Python code:

```Python
from weakref import WeakValueDictionary

class DataModelScriptDebugStackInternal:
    _cache = WeakValueDictionary()

    @classmethod
    def instance_for(cls, data):
        return cls._lazy_weak_cache(data)

    @staticmethod
    def _lazy_weak_cache(cache, data, factory):
        if id(data) not in cache:
            cache[id(data)] = factory()
        return cache[id(data)]

    PREFERRED_DATA_SPACES_IIDS = {
        IIDs.IDATA_MODEL_SCRIPT_DEBUG_STACK: WrapIDataModelScriptDebugStack,
    }

    @staticmethod
    def try_preferred_interfaces(supplier):
        return DataModelScriptDebugStackInternal._try_preferred_interfaces(DataModelScriptDebugStackInternal, supplier)

    @classmethod
    def _try_preferred_interfaces(cls, cls_, preferred_iids, supplier):
        for iid in sorted(preferred_iids.keys()):
            if isinstance(iid, IIDs) and issubclass(supplier(), preferred_iids[iid]):
                return cls_(supplier())
        return None

class WrapIDataModelScriptDebugStack:
    pass
```

Note that Python does not have direct equivalents to Java's `Map` or `ImmutableMap`, so we use a dictionary (`WeakValueDictionary`) for caching and another dictionary for storing preferred interfaces. The `try_preferred_interfaces` method is also implemented differently, as it needs to check the type of each interface ID against the supplier function.