from weakref import WeakValueDictionary as WeakValueHashMap
import immutable as ImmutableMap

class DebugHostSymbolEnumeratorInternal:
    CACHE = WeakValueHashMap()

    @classmethod
    def instance_for(cls, data):
        return DbgModelUtil.lazy_weak_cache(DebugHostSymbolEnumeratorInternal.CACHE, data, lambda: cls())

    PREFERRED_DATA_SPACES_IIDS_BUILDER = ImmutableMap.builder()
    PREFERRED_DATA_SPACES_IIDS = PREFERRED_DATA_SPACES_IIDS_BUILDER \
                                    .put({IDebugHostSymbolEnumerator.IID_IDEBUG_HOST_SYMBOL_ENUMERATOR}, WrapIDebugHostSymbolEnumerator) \
                                    .build()

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return DbgModelUtil.try_preferred_interfaces(DebugHostSymbolEnumeratorInternal, PREFERRED_DATA_SPACES_IIDS, supplier)
