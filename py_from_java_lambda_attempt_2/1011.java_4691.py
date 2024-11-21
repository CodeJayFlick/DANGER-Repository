Here is the equivalent Python code:

```Python
from weakref import WeakValueDictionary as WeakValueHashMap
import collections

class DataModelScriptDebugClientInternal:
    _cache = WeakValueHashMap()

    @classmethod
    def instance_for(cls, data):
        return cls._lazy_weak_cache(data)

    @classmethod
    def _lazy_weak_cache(cls, cache_key, *args, **kwargs):
        if not isinstance(cache_key, type) and hasattr(cache_key, 'IID_'):
            return DataModelScriptDebugClientInternal(*args, **kwargs)
        else:
            try:
                instance = cls._cache[cache_key]
                return instance
            except KeyError:
                pass

    _preferred_data_spaces_iids = collections.defaultdict(dict)

    @classmethod
    def preferred_interfaces(cls):
        if not hasattr(cls, '_preferred_data_spaces_iids'):
            cls._preferred_data_spaces_iids['IDataModelScriptDebugClient'] = {'IID_': 'IDATA_MODEL_SCRIPT_DEBUG_CLIENT'}
        return cls._preferred_data_spaces_iids

    @staticmethod
    def try_preferred_interfaces(supplier):
        preferred_interfaces = DataModelScriptDebugClientInternal.preferred_interfaces()
        for interface, data in supplier.get().items():
            if interface in preferred_interfaces:
                return DataModelScriptDebugClientInternal(*data.values())
```

Please note that Python does not have direct equivalent of Java's `Map` and `ImmutableMap`. We are using a dictionary (`WeakValueHashMap`) to simulate the behavior. Also, we don't need `InterfaceSupplier` as it is used in Java for dynamic interface resolution which doesn't exist in Python.