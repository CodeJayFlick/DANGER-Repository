from weakref import WeakValueDictionary as WeakValueHashMap
import functools

class DataModelScriptManagerInternal:
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

    PREFERRED_DATA_SPACES_IIDS = {
        REFIID(IID_IDATA_MODEL_SCRIPT_MANAGER): WrapIDataModelScriptManager,
    }

    @staticmethod
    def try_preferred_interfaces(supplier):
        return DataModelScriptManagerInternal._try_preferred_interfaces(DataModelScriptManagerInternal, 
            DataModelScriptManagerInternal.PREFERRED_DATA_SPACES_IIDS, supplier)

    @classmethod
    def _try_preferred_interfaces(cls, cls_, preferred_iids, supplier):
        for iid in sorted(preferred_iids.keys()):
            try:
                return cls_.instance_for(supplier.get(iid))
            except KeyError:
                pass
        return None

class REFIID:
    IID_IDATA_MODEL_SCRIPT_MANAGER = 'IID_IDATA_MODEL_SCRIPT_MANAGER'

IIDs = {
    REFIID.IID_IDATA_MODEL_SCRIPT_MANAGER: WrapIDataModelScriptManager,
}
