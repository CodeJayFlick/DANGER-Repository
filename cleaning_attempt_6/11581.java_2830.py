class FloatFormatFactory:
    cache = {}

    def get_float_format(self, size):
        if size in self.cache:
            return self.cache[size]
        else:
            format = FloatFormat(size)
            self.cache[size] = format
            return format


# This is a simple implementation of the FloatFormat class. In real-world scenarios,
# this would be an interface with multiple implementations for different float formats.
class FloatFormat:
    def __init__(self, size):
        pass

    # You might want to add some methods here depending on what you need your
    # FloatFormat objects to do.

try:
    from functools import lru_cache
except ImportError:
    print("This Python version does not support the @lru_cache decorator.")
else:
    def get_float_format(size):
        return cache.get(size, lambda: FloatFormat(size))
