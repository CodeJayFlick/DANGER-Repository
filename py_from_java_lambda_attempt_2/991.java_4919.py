Here is the equivalent Python code:

```Python
from weakref import WeakValueDictionary as WeakValueHashMap
import immutable

class DataModelScriptClientInternal:
    _cache = WeakValueHashMap()

    @classmethod
    def instance_for(cls, data):
        return cls._lazy_weak_cache(_cache, data)

    PREFERRED_DATA_SPACES_IIDS = immutable.Map.builder()
    PREFERRED_DATA_SPACES_IIDS.put(REFIID(IID_IDATA_MODEL_SCRIPT_CLIENT), WrapIDataModelScriptClient)
    PREFERRED_DATA_SPACES_IIDS.build()

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return cls._try_preferred_interfaces(DataModelScriptClientInternal, _cache, supplier)

class REFIID:
    IID_IDATA_MODEL_SCRIPT_CLIENT = None

def DbgModelUtil_lazy_weak_cache(cache, data, new_func):
    if cache.get(data) is not None:
        return cache[data]
    else:
        result = new_func()
        cache[data] = result
        return result

def DbgModelUtil_try_preferred_interfaces(cls, preferred_iids, supplier):
    # implement this method as per your requirement
    pass

class WrapIDataModelScriptClient:
    pass

IID_IDATA_MODEL_SCRIPT_CLIENT = None  # define IID_IDATA_MODEL_SCRIPT_CLIENT here
```

Please note that the `ImmutableMap` and `REFIID` classes are not built-in Python types, so you would need to implement them or use a library like `dataclasses` which provides similar functionality.