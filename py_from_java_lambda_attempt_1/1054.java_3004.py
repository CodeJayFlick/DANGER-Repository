Here is the translation of the given Java code into equivalent Python:

```Python
from weakref import WeakValueDictionary as WeakValueHashMap
import collections

class DebugHostStatusInternal:
    _cache = WeakValueHashMap()

    @classmethod
    def instance_for(cls, data):
        return cls._lazy_weak_cache(data)

    @classmethod
    def _lazy_weak_cache(cls, cache, data, factory):
        if id(data) not in cache:
            cache[id(data)] = factory()
        return cache[id(data)]

    _preferred_data_spaces_iids_builder = collections.defaultdict(dict)
    _preferred_data_spaces_iids = {}

    @property
    def preferred_data_spaces_iids(self):
        return self._preferred_data_spaces_iids

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return cls._try_preferred_interfaces(cls.__name__, cls._preferred_data_spaces_iids, supplier)

    @classmethod
    def _try_preferred_interfaces(cls, class_name, preferred_data_spaces_iids, supplier):
        for i_id, interface in preferred_data_spaces_iids.items():
            if isinstance(supplier(), interface):
                return DebugHostStatusInternal()
        return None

```

Note that Python does not have direct equivalents to Java's `Map` and `ImmutableMap`, so I used a dictionary (`_cache`) from the `weakref` module for caching, and a defaultdict from the `collections` module for building up the `_preferred_data_spaces_iids`.