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
