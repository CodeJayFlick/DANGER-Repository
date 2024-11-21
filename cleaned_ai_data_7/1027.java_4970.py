from weakref import WeakValueDictionary as WeakValueHashMap
import immutable

class DebugHostContextInternal:
    _cache = WeakValueHashMap()

    @classmethod
    def instance_for(cls, data):
        return cls._lazy_weak_cache(_cache, data)

    PREFERRED_DATA_SPACES_IIDS_BUILDER = immutable.Map.builder()
    PREFERRED_DATA_SPACES_IIDS = PREFERRED_DATA_SPACES_IIDS_BUILDER \
                                    .put((IDebugHostContext.IID_IDBUG_HOST_CONTEXT,), WrapIDebugHostContext) \
                                    .build()

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return cls._try_preferred_interfaces(DebugHostContextInternal, PREFERRED_DATA_SPACES_IIDS, supplier)

# Helper methods

def _lazy_weak_cache(cache, data):
    # Implementation of lazyWeakCache method from Java code.
    pass

def _try_preferred_interfaces(cls, preferred_data_spaces_iids, supplier):
    # Implementation of tryPreferredInterfaces method from Java code.
    pass
