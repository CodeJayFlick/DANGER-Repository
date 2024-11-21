from weakref import WeakValueDictionary as CACHE
import collections.abc as immutable_collections

class DebugHostConstantInternal:
    _CACHE = CACHE()

    @classmethod
    def instance_for(cls, data):
        return DbgModelUtil.lazy_weak_cache(cls._CACHE, data, lambda: cls())

    _PREFERRED_DATA_SPACES_IIDS_BUILDER = immutable_collections.defaultdict(lambda: None)
    _PREFERRED_DATA_SPACES_IIDS = {new_idebug_host_constant_iid(): WrapIDebugHostConstant}

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return DbgModelUtil.try_preferred_interfaces(cls.__class__, cls._PREFERRED_DATA_SPACES_IIDS, supplier)

def new_idebug_host_constant_iid():
    # This is a placeholder for the actual implementation of IDebugHostConstant.IID_IDDEBUG_HOST_CONSTANT
    pass

# Assuming these are defined elsewhere in your codebase:
DbgModelUtil = ...
WrapIDebugHostConstant = ...

