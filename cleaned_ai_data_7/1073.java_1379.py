from weakref import WeakValueDictionary as CACHE
import functools

class KeyStoreInternal:
    PREFERRED_DATA_SPACES_IIDS = {
        'IKey_Store': WrapIKeyStore,
    }

    @functools.lru_cache(maxsize=None)
    def instance_for(data):
        return DbgModelUtil.lazy_weak_cache(CACHE, data, lambda: KeyStoreImpl())

    try_preferred_interfaces = staticmethod(functools.partial(DbgModelUtil.try_preferred_interfaces, class_=KeyStoreInternal))

class WrapIKeyStore:
    pass

class REFIID:
    def __init__(self, iid):
        self.iid = iid
