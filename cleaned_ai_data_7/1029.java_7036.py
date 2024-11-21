from weakref import WeakValueDictionary as WeakMap
import collections

class DebugHostDataInternal:
    _cache = WeakMap()

    @classmethod
    def instance_for(cls, data):
        return cls._lazy_weak_cache(data)

    @classmethod
    def _lazy_weak_cache(cls, cache_key, factory):
        if cache_key not in cls._cache:
            cls._cache[cache_key] = factory()
        return cls._cache[cache_key]

    PREFERRED_DATA_SPACES_IIDS = collections.defaultdict(dict)
    PREFERRED_DATA_SPACES_IIDS[IDebugHostData.IID_IDBUG_HOST_DATA] = WrapIDebugHostData

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return cls._try_preferred_interfaces(DebugHostDataInternal.__class__, 
                                             cls.PREFERRED_DATA_SPACES_IIDS, supplier)

    @classmethod
    def _try_preferred_interfaces(cls, target_class, preferred_iids, supplier):
        # implement this method as per your requirement
        pass

