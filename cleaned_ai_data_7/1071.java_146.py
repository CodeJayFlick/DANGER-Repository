import weakref

class KeyEnumeratorInternal:
    _cache = weakref.WeakValueDictionary()

    @classmethod
    def instance_for(cls, data):
        return DbgModelUtil.lazy_weak_cache(KeyEnumeratorInternal._cache, data, lambda: cls())

    PREFERRED_DATA_SPACES_IIDS = {}

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return DbgModelUtil.try_preferred_interfaces(cls, KeyEnumeratorInternal.PREFERRED_DATA_SPACES_IIDS, supplier)
