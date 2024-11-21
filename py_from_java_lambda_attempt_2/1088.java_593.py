Here is the translation of the Java code into equivalent Python:

```Python
from weakref import WeakValueDictionary as WeakValueHashMap
import immutable

class UnknownExInternal:
    _cache = WeakValueHashMap()

    @classmethod
    def instance_for(cls, data):
        return cls._lazy_weak_cache(_cache, data)

    PREFERRED_DATA_SPACES_IIDS = immutable.Map.builder()
    .put(REFIID(IUnknown.IID_IUNKNOWN), WrapIUnknownEx)
    ._build()

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return DbgModelUtil.try_preferred_interfaces(UnknownExInternal, cls._PREFERRED_DATA_SPACES_IIDS, supplier)

class REFIID:
    IID_IUNKNOWN = 'IID_IUNKNOWN'

class WrapIUnknownEx:
    pass

def DbgModelUtil_try_preferred_interfaces(cls, preferred_data_spaces_iids, supplier):
    # implementation of tryPreferredInterfaces method
    pass

# usage example:

data = WrapIUnknownEx()
unknown_ex_internal_instance = UnknownExInternal.instance_for(data)
```

Please note that the `DbgModelUtil` and its methods (`try_preferred_interfaces`) are not implemented in this translation, as they were part of a larger Java codebase. You would need to implement these functions according to your specific requirements.

Also, Python does not have direct equivalent for Java's `ImmutableMap`. The above implementation uses the `immutable.Map.builder()` from the `immutable` library which is used to create an immutable map in Python.