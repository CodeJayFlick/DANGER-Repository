Here is the translation of the given Java code into equivalent Python:

```Python
from weakref import WeakValueDictionary as CACHE
import collections

class DebugHostTypeInternal:
    PREFERRED_DATA_SPACES_IIDS = {
        IDebugHostType2.IID_IDEBUG_HOST_TYPE2: WrapIDebugHostType2,
        IDebugHostType1.IID_IDEBUG_HOST_TYPE: WrapIDebugHostType1
    }

    @classmethod
    def instance_for(cls, data):
        return DbgModelUtil.lazy_weak_cache(CACHE, data)

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return DbgModelUtil.try_preferred_interfaces(DebugHostTypeInternal.__class__, DebugHostTypeInternal.PREFERRED_DATA_SPACES_IIDS, supplier)


# assuming these classes exist in the same module:
class WrapIDebugHostType1:
    pass

class WrapIDebugHostType2:
    pass

class IDebugHostType1:
    IID_IDEBUG_HOST_TYPE = None
    pass

class IDebugHostType2:
    IID_IDEBUG_HOST_TYPE2 = None
    pass

# assuming this class exists in the same module:
def DbgModelUtil():
    def lazy_weak_cache(cache, data):
        # implement your logic here
        return cache.get(data)

    @classmethod
    def try_preferred_interfaces(cls, cls_, preferred_data_spaces_iids, supplier):
        # implement your logic here
        pass

class REFIID:
    def __init__(self, iid):
        self.iid = iid

# assuming this class exists in the same module:
def ImmutableMap():
    return collections.defaultdict(dict)
```

Please note that you need to have equivalent classes and functions defined for `WrapIDebugHostType1`, `WrapIDebugHostType2`, `IdDebugHostType1`, `IdDebugHostType2` and `DbgModelUtil`.