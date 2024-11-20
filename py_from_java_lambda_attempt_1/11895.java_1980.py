Here is the translation of the Java code into Python:

```Python
import weakref
from collections import unmodifiable_collection

class LazyLoadingCachingMap:
    def __init__(self):
        self.lock = None
        self.soft_ref = None

    def put(self, key, value):
        if not hasattr(self, 'map'):
            return
        map_ = getattr(self, 'map')
        map_[key] = value

    def remove(self, key):
        if not hasattr(self, 'map') or not self.map:
            return
        map_ = getattr(self, 'map')
        del map_[key]

    def clear(self):
        if hasattr(self, 'soft_ref'):
            setattr(self, 'soft_ref', None)

    def get_or_load_map(self):
        if hasattr(self, 'map'):
            return getattr(self, 'map')

        self.lock.acquire()
        try:
            if not hasattr(self, 'map') or not self.map:
                map_ = self.load_map()
                self.map = weakref.ref(map_)
        finally:
            self.lock.release()

    def get_or_load_value(self, key):
        return getattr(self.get_or_load_map(), {}).get(key)

    def values(self):
        if hasattr(self, 'map'):
            return unmodifiable_collection(getattr(self, 'map').values())

    def load_map(self):
        # This method should be implemented by the subclass
        pass

class Lock:
    def acquire(self):
        # Implement your locking mechanism here
        pass

    def release(self):
        # Release the lock
        pass


# Example usage:

class MyLazyLoadingCachingMap(LazyLoadingCachingMap, Lock):
    def load_map(self):
        # Load map data from scratch. This method should be implemented by the subclass.
        return {}

my_lazy_loading_caching_map = MyLazyLoadingCachingMap()
```

Note that Python does not have built-in support for generics like Java has with its `<K>` and `<V>` syntax, so I've omitted those in this translation.