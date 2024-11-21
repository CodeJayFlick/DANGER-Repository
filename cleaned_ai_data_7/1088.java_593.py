from weakref import WeakValueDictionary as WeakValueHashMap
import immutable

class UnknownExInternal:
    _cache = WeakValueHashMap()

    @classmethod
    def instance_for(cls, data):
        return cls._lazy_weak_cache(_cache, data)

    PREFERRED_DATA_SPACES_IIDS = immutable.Map.builder()
    .put(REFIID(IUnknown.IID_IUNKNOWN), WrapIUnknownEx)
    ._build()

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return DbgModelUtil.try_preferred_interfaces(UnknownExInternal, cls._PREFERRED_DATA_SPACES_IIDS, supplier)

class REFIID:
    IID_IUNKNOWN = 'IID_IUNKNOWN'

class WrapIUnknownEx:
    pass

def DbgModelUtil_try_preferred_interfaces(cls, preferred_data_spaces_iids, supplier):
    # implementation of tryPreferredInterfaces method
    pass

# usage example:

data = WrapIUnknownEx()
unknown_ex_internal_instance = UnknownExInternal.instance_for(data)
