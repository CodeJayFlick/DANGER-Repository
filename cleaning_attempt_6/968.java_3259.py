from weakref import WeakValueDictionary as CACHE
import collections.abc as map_module
from functools import lru_cache as lazy_weak_cache

class ComparableConceptInternal:
    _cache = CACHE()

    @classmethod
    def instance_for(cls, data):
        return cls._lazy_weak_cache(cls._cache, data)

    @lru_cache(maxsize=None)
    def _lazy_weak_cache(self, cache, data):
        # equivalent to DbgModelUtil. lazyWeakCache(CACHE, data, ComparableConceptImpl::new);
        pass

    PREFERRED_DATA_SPACES_IIDS = collections.defaultdict(dict)

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return cls._try_preferred_interfaces(ComparableConceptInternal, 
                                             cls.PREFERRED_DATA_SPACES_IIDS, supplier)
    
    @staticmethod
    def _try_preferred_interfaces(cls, class_obj, preferred_data_spaces_iids, supplier):
        # equivalent to DbgModelUtil. tryPreferredInterfaces(ComparableConceptInternal.class,
        # PREFERRED_ DATA_ SPACES_ IIDS, supplier);
        pass

# Usage example:
data = 'some data'
concept_instance = ComparableConceptInternal.instance_for(data)
