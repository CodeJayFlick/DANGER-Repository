Here is the translation of the given Java code into equivalent Python:

```Python
from weakref import WeakValueDictionary as CACHE
import collections.abc as ImmutableMap

class HostDataModelAccessInternal:
    PREFERRED_DATA_SPACES_IIDS = {
        REFIID(IHostDataModelAccess.IID_IHOST_DATA_MODEL_ACCESS): WrapIHostDataModelAccess,
    }

    @classmethod
    def instance_for(cls, data):
        return DbgModelUtil.lazy_weak_cache(CACHE, data, lambda: cls())

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return DbgModelUtil.try_preferred_interfaces(HostDataModelAccessInternal, HostDataModelAccessInternal.PREFERRED_DATA_SPACES_IIDS, supplier)

class REFIID:
    IID_IHOST_DATA_MODEL_ACCESS = None

class WrapIHostDataModelAccess:
    pass
```

Note that this translation is not a direct conversion from Java to Python. It's more of an equivalent implementation in Python. Some parts like `Map` and `ImmutableMap` are replaced with Python dictionaries, while some methods have been modified according to the way they work in Python.

Also note that you will need to implement the following classes:

- `DbgModelUtil`
- `InterfaceSupplier`

These classes were not provided in your original Java code.