from collections import OrderedDict

class FixedSizeMRUCachingFactory:
    def __init__(self, factory, size):
        self.delegate = factory
        self.cache = OrderedDict(maxlen=size)

    def get(self, key):
        value = self.cache.get(key)
        if value is not None:
            return value

        value = self.delegate.get(key)
        self.cache[key] = value  # equivalent to put in Java
        return value
