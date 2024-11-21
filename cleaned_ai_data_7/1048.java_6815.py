from weakref import WeakValueDictionary as WeakHashMap
import immutable

class DebugHostModuleSignatureInternal:
    _cache = WeakHashMap()

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

    PREFERRED_DATA_SPACES_IIDS = immutable.Map()

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return cls._try_preferred_interfaces(cls.__class__, cls.PREFERRED_DATA_SPACES_IIDS, supplier)

    @staticmethod
    def _try_preferred_interfaces(cls, preferred_data_spaces_iids, supplier):
        for iid in preferred_data_spaces_iids:
            if iid in supplier:
                return supplier[iid]
        return None

# Usage example:

class WrapIDebugHostModuleSignature:
    pass

class IDebugHostModuleSignature:
    IID_IDEBUG_HOST_MODULE_SIGNATURE = "some iid"

PREFERRED_DATA_SPACES_IIDS = {
    IDEBUG_HOST_MODULE_SIGNATURE.IID_IDEBUG_HOST_MODULE_SIGNATURE: WrapIDebugHostModuleSignature,
}

supplier = {"iid": WrapIDebugHostModuleSignature}
result = DebugHostModuleSignatureInternal.try_preferred_interfaces(supplier)
