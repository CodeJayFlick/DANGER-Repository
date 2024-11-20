from collections import defaultdict, OrderedDict
import asyncio

class AsyncLazyMap:
    def __init__(self, map: dict, function):
        self.map = map
        self.unmodifiable_map = {k: v for k, v in map.items()}
        self.futures = defaultdict(lambda: None)
        self.function = function

    class KeyedFuture:
        def __init__(self, key, value=None):
            self.key = key
            if value is not None:
                self.complete(value)

        async def complete(self, value):
            return value

        @property
        def get_key(self):
            return self.key

    def put_future(self, key: object, future: 'AsyncLazyMap.KeyedFuture'):
        self.futures[key] = future

    def forget_errors(self, predicate):
        self.predicate_forget_errors = predicate
        return self

    async def get(self, key: object, func=None) -> asyncio.Future:
        if not isinstance(key, str):
            raise TypeError("Key must be a string")
        future = self.futures.get(key)
        if future is None or not future.is_done():
            f = AsyncLazyMap.KeyedFuture(key)
            self.put_future(key, f)
            dep = await (func.apply(key) if func else asyncio.Future())
            f.future = dep
            dep.handle(f.complete)
            return f
        elif not self.predicate_forget_errors.get_key and future.is_done():
            return future

    async def put(self, key: object):
        if not isinstance(key, str):
            raise TypeError("Key must be a string")
        future = self.futures.get(key)
        if future is None:
            f = AsyncLazyMap.KeyedFuture(key)
            self.put_future(key, f)
            return f
        else:
            return future

    def forget(self, key: object) -> asyncio.Future:
        del self.map[key]
        return self.futures.pop(key)

    async def remove(self, key: str):
        if not isinstance(key, str):
            raise TypeError("Key must be a string")
        f = self.futures.get(key)
        v = self.map.pop(key)
        if f is not None:
            await f.cancel()
        return v

    @property
    def get_completed_map(self) -> dict:
        return {k: v for k, v in self.map.items()}

    async def clear(self):
        copy_futures = list(self.futures.values())
        del self.futures[:]
        del self.map[:]
        for f in copy_futures:
            await f.cancel()

    @property
    def get_pending_key_set(self) -> set:
        return {f.key for f in self.futures.values() if not f.is_done()}

    async def retain_keys(self, keys: list):
        removed = [k for k, v in self.futures.items() if k not in keys]
        del self.map[k] for k in removed
        del self.futures[k] for k in removed

    @property
    def contains_key(self, key: str) -> bool:
        return key in self.map or any(f.key == key for f in self.futures.values())
