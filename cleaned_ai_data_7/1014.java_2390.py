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
