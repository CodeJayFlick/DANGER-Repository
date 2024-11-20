from weakref import WeakValueDictionary as CACHE
import collections.abc as ImmutableMap

class HostDataModelAccessInternal:
    PREFERRED_DATA_SPACES_IIDS = {
        REFIID(IHostDataModelAccess.IID_IHOST_DATA_MODEL_ACCESS): WrapIHostDataModelAccess,
    }

    @classmethod
    def instance_for(cls, data):
        return DbgModelUtil.lazy_weak_cache(CACHE, data, lambda: cls())

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return DbgModelUtil.try_preferred_interfaces(HostDataModelAccessInternal, HostDataModelAccessInternal.PREFERRED_DATA_SPACES_IIDS, supplier)

class REFIID:
    IID_IHOST_DATA_MODEL_ACCESS = None

class WrapIHostDataModelAccess:
    pass
