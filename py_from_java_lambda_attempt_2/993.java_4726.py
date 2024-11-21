Here is the translation of the given Java code into equivalent Python:

```Python
from weakref import WeakValueDictionary as WeakValueHashMap
import collections

class DataModelScriptHostContextInternal:
    _cache = WeakValueHashMap()

    @classmethod
    def instance_for(cls, data):
        return cls._lazy_weak_cache(data)

    @staticmethod
    def _lazy_weak_cache(cache, data, factory):
        try:
            return cache[data]
        except KeyError:
            result = factory()
            cache[data] = result
            return result

    PREFERRED_DATA_SPACES_IIDS = collections.defaultdict(dict)
    PREFERRED_DATA_SPACES_IIDS[IDataModelScriptHostContext.IID_IDATA_MODEL_SCRIPT_HOST_CONTEXT] = WrapIDataModelScriptHostContext.__class__

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return cls._try_preferred_interfaces(DataModelScriptHostContextInternal, 
                                             cls.PREFERRED_DATA_SPACES_IIDS, supplier)

    @staticmethod
    def _try_preferred_interfaces(cls, preferred_classes, supplier):
        for interface_id in sorted(preferred_classes.keys()):
            if interface_id in supplier:
                return DataModelScriptHostContextInternal()
        return None

class REFIID:
    pass  # Assuming this is a class that can be instantiated with IID_... methods
```

Please note that Python does not have direct equivalent of Java's `Map` and `ImmutableMap`. Instead, we use the built-in dictionary (`dict`) for regular maps and `defaultdict` from the `collections` module to create an immutable map. Also, there is no exact equivalent of Java's `InterfaceSupplier`, so I've replaced it with a simple method that takes a supplier as argument.

The code also assumes that you have classes like `WrapIDataModelScriptHostContext` and `DataModelScriptHostContextImpl`.