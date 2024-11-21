import random
from collections import defaultdict

class RandomDeleteCache:
    def __init__(self, cache_size):
        self.cache_size = cache_size
        self.cache = {}

    def get(self, key):
        value = self.cache.get(key)
        if value is None:
            self.random_remove_object_if_cache_is_full()
            value = self.load_object_by_key(key)
            self.cache[key] = value
        return value

    def random_remove_object_if_cache_is_full(self):
        if len(self.cache) == self.cache_size:
            self.remove_first_object()

    def remove_first_object(self):
        if not self.cache:
            return
        key = next(iter(self.cache))
        del self.cache[key]

    def load_object_by_key(self, key):
        # This method should be implemented by the subclass
        raise NotImplementedError

    def remove_object(self, key):
        del self.cache[key]

    def clear(self):
        self.cache.clear()

    def size(self):
        return len(self.cache)
