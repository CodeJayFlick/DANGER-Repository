from weakref import WeakValueDictionary as WeakValueHashMap
import immutable

class DebugHostErrorSinkInternal:
    _cache = WeakValueHashMap()

    @classmethod
    def instance_for(cls, data):
        return cls._lazy_weak_cache(_cache, data)

    PREFERRED_DATA_SPACES_IIDS_BUILDER = immutable.Map.builder()
    PREFERRED_DATA_SPACES_IIDS = PREFERRED_DATA_SPACES_IIDS_BUILDER \
                                    .put(REFIID(IDebugHostErrorSink.IID_IDBUG_HOST_ERROR_SINK), 
                                         WrapIDebugHostErrorSink) \
                                    .build()

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return cls._try_preferred_interfaces(DebugHostErrorSinkInternal, PREFERRED_DATA_SPACES_IIDS, supplier)

# Helper methods

def _lazy_weak_cache(cache, data, constructor=None):
    if isinstance(data, tuple) and len(data) == 2:
        key = data[0]
        value = data[1]
        return cache.get(key)
    else:
        instance = cache.setdefault(id(data), constructor(*data))
        return instance

def _try_preferred_interfaces(cls, preferred_iids, supplier):
    for i in reversed(range(len(preferred_iids))):
        interface_id = list(preferred_iids.keys())[i]
        if isinstance(interface_id, REFIID) and interface_id.IID == IDebugHostErrorSink.IID_IDBUG_HOST_ERROR_SINK:
            return cls.instance_for(supplier.get())
    return None

class WrapIDebugHostErrorSink:
    pass

class InterfaceSupplier:
    def get(self):
        raise NotImplementedError
