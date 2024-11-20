from weakref import WeakValueDictionary as WeakHashMap

class X_DebugHostBaseClassInternal:
    _cache = WeakHashMap()

    @classmethod
    def instance_for(cls, data):
        return DbgModelUtil.lazy_weak_cache(_cache, data)

    PREFERRED_DATA_SPACES_IIDS = {}

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return DbgModelUtil.try_preferred_interfaces(X_DebugHostBaseClassInternal.__class__, _cache, supplier)
