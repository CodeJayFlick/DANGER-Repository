Here is the translation of the Java code to Python:
```python
import weakref
from collections import defaultdict

class DataModelScriptDebugInternal:
    _cache = weakref.WeakValueDictionary()

    @classmethod
    def instance_for(cls, data):
        return cls._lazy_weak_cache(data)

    @staticmethod
    def _lazy_weak_cache(cache, data, factory):
        if cache.get(data) is None:
            cache[data] = factory()
        return cache[data]

    PREFERRED_DATA_SPACES_IIDS = defaultdict(dict)
    PREFERRED_DATA_SPACES_IIDS[IDataModelScriptDebug2.IID_IDATA_MODEL_SCRIPT_DEBUG2] = WrapIDataModelScriptDebug
    PREFERRED_DATA_SPACES_IIDS[IDataModelScriptDebug.IID_IDATA_MODEL_SCRIPT_DEBUG] = WrapIDataModelScriptDebug

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return cls._try_preferred_interfaces(DataModelScriptDebugInternal.__class__, cls.PREFERRED_DATA_SPACES_IIDS, supplier)

    @staticmethod
    def _try_preferred_interfaces(cls, preferred_iids, supplier):
        for iid in preferred_iids:
            if iid in supplier:
                return supplier[iid]
        return None

# Note: WrapIDataModelScriptDebug and IDataModelScriptDebug2 are not defined here,
# they should be replaced with the actual Python classes or modules
```
Note that I had to make some assumptions about the Java code, as it's not possible to translate 1-to-1. For example:

* `Map<Pointer, DataModelScriptDebugInternal>` is equivalent to a dictionary in Python.
* `ImmutableMap.Builder` and `PREFERRED_DATA_SPACES_IIDS_BUILDER` are equivalent to creating an empty defaultdict in Python.
* The Java code uses JNA (Java Native Access) which has no direct equivalent in Python. I assume that the necessary imports and classes will be provided elsewhere.

Also, this translation assumes that you have a similar class hierarchy as in the original Java code, with `WrapIDataModelScriptDebug` being a subclass of some interface or abstract base class.