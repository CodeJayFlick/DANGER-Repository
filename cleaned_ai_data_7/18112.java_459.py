from abc import ABC, abstractmethod

class Cache(ABC):
    @abstractmethod
    def get(self, key: object) -> object:
        """Get an item from the cache by its key"""
        raise NotImplementedError("Must be implemented")

    @abstractmethod
    def clear(self) -> None:
        """Clear all items in the cache"""
        pass

class CacheException(Exception):
    pass

try:
    import io
except ImportError:  # Python < 3.7
    import StringIO as io
else:
    import io
