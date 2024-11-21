from weakref import WeakValueDictionary as WeakValueHashMap
import collections

class DebugHostTypeSignatureInternal:
    _cache = WeakValueHashMap()

    @classmethod
    def instance_for(cls, data):
        return cls._lazy_weak_cache(cls._cache, data)

    PREFERRED_DATA_SPACES_IIDS = collections.defaultdict(lambda: None)
    PREFERRED_DATA_SPACES_IIDS[IDIebugHostTypeSignature.IID_IDBUG_HOST_TYPE_SIGNATURE] = WrapIDebugHostTypeSignature

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return cls._try_preferred_interfaces(DebugHostTypeSignatureInternal.__class__, cls.PREFERRED_DATA_SPACES_IIDS, supplier)

    @classmethod
    def _lazy_weak_cache(cls, cache, data):
        # implement the lazy weak caching logic here
        pass

    @classmethod
    def _try_preferred_interfaces(cls, class_type, preferred_data_spaces_iids, supplier):
        # implement the try preferred interfaces logic here
        pass


class WrapIDebugHostTypeSignature:
    pass


class IDebugHostTypeSignature:
    IID_IDBUG_HOST_TYPE_SIGNATURE = None

# Usage example:

wrap_id_debug_host_type_signature = WrapIDebugHostTypeSignature()
debug_host_type_signature_internal_instance = DebugHostTypeSignatureInternal.instance_for(wrap_id_debug_host_type_signature)
