from weakref import WeakValueDictionary as WeakValueHashMap
import collections

class DebugHostSymbolsInternal:
    _cache = WeakValueHashMap()

    @classmethod
    def instance_for(cls, data):
        return DbgModelUtil.lazy_weak_cache(_cache, data, lambda: cls())

    PREFERRED_DATA_SPACES_IIDS_BUILDER = collections.defaultdict(dict)
    PREFERRED_DATA_SPACES_IIDS = {}

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return DbgModelUtil.try_preferred_interfaces(cls.__name__, PREFERRED_DATA_SPACES_IIDS, supplier)

class DbgModelUtil:
    @staticmethod
    def lazy_weak_cache(cache, data, factory):
        # implementation of this method is not provided in the given Java code,
        # so it's left as a placeholder for now.
        pass

    @classmethod
    def try_preferred_interfaces(cls, class_name, preferred_data_spaces_iids, supplier):
        # implementation of this method is not provided in the given Java code,
        # so it's left as a placeholder for now.
        pass
