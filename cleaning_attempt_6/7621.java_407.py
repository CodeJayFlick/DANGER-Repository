class FIDFixedSizeMRUCachingFactory:
    def __init__(self, factory, size):
        self.delegate = factory
        self.cache = {}

    def get(self, func):
        entry_point = func.get_entry_point()
        
        if entry_point in self.cache:
            return self.cache[entry_point]
        
        value = self.delegate.get(func)
        if value is None:
            return None
        
        self.cache[entry_point] = value
        return value

# Note: Python does not have a direct equivalent to Java's LRUMap. The cache will be implemented as a dictionary in this translation.
