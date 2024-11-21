from weakref import WeakValueDictionary as CACHE
import functools

class DebugHostModuleInternal:
    _CACHE = CACHE()

    @classmethod
    def instance_for(cls, data):
        return cls._lazy_weak_cache(data)

    @classmethod
    def _lazy_weak_cache(cls, data):
        if isinstance(data, WrapIDebugHostModule1):
            return cls.new_DebugHostModuleImpl1()
        elif isinstance(data, WrapIDebugHostModule2):
            return cls.new_DebugHostModuleImpl2()

    PREFERRED_DATA_SPACES_IIDS = {}
    for iid in [new_IDebugHostModule2_IID_IDEBUG_HOST_MODULE2(), new_IDebugHostModule1_IID_IDEBUG_HOST_MODULE()]:
        if iid == IDebugHostModule2.IID_DEBUG_HOST_MODULE2:
            PREFERRED_DATA_SPACES_IIDS[iid] = WrapIDebugHostModule2
        elif iid == IDebugHostModule1.IID_DEBUG_HOST_MODULE:
            PREFERRED_DATA_SPACES_IIDS[iid] = WrapIDebugHostModule1

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return cls._try_preferred_interfaces(DebugHostModuleInternal.__class__, cls.PREFERRED_DATA_SPACES_IIDS, supplier)

    @classmethod
    def _try_preferred_interfaces(cls, class_, data_spaces_iids, supplier):
        return DbgModelUtil.try_preferred_interfaces(class_, data_spaces_iids, supplier)
