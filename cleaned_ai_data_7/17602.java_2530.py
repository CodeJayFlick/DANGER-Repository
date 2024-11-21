class CachedStringPool:
    _cached_pool = {}

    def get_cached_pool(self):
        return self._cached_pool

    @classmethod
    def get_instance(cls):
        if not hasattr(CachedStringPool, "_instance"):
            CachedStringPool._instance = cls()
        return CachedStringPool._instance


CachedStringPool._instance = None  # Initialize the instance holder
