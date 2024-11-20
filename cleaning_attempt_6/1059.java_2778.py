import weakref
from collections import defaultdict

class DebugHostSymbolInternal:
    _cache = weakref.WeakValueDictionary()

    @classmethod
    def instance_for(cls, data):
        return cls._lazy_weak_cache(data)

    @classmethod
    def _lazy_weak_cache(cls, data):
        try:
            return _cache[data]
        except KeyError:
            if isinstance(data, WrapIDebugHostSymbol1):
                result = DebugHostSymbolImpl1()
            elif isinstance(data, WrapIDebugHostSymbol2):
                result = DebugHostSymbolImpl2()
            else:
                raise ValueError("Unknown data type")
            _cache[data] = weakref.ref(result)
            return result

    PREFERRED_DATA_SPACES_IIDS = defaultdict(dict)

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return cls._try_preferred_interfaces(supplier)

    @classmethod
    def _try_preferred_interfaces(cls, supplier):
        for iid, interface in DebugHostSymbolInternal.PREFERRED_DATA_SPACES_IIDS.items():
            if isinstance(iid, REFIID) and issubclass(interface, WrapIDebugHostSymbol1):
                return DbgModelUtil.try_preferred_interfaces(DebugHostSymbolInternal, PREFERRED_DATA_SPACES_IIDS, supplier)
        raise ValueError("No preferred interfaces found")
