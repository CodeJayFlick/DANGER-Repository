Here is the translation of the Java code to Python:
```python
import range

class DBCachedObjectStoreValueSubCollection(T):
    def __init__(self, store: 'DBCachedObjectStore[T]', err_handler: ErrorHandler, lock: ReadWriteLock, direction: Direction, key_range: Range[Long]):
        super().__init__(store, err_handler, lock, direction)
        self.key_range = key_range

    @property
    def size(self) -> int:
        return len(store.get_keys(key_range))

    @property
    def is_empty(self) -> bool:
        return not store.keys_exist(key_range)

    def contains(self, o: object) -> bool:
        with lock.read_lock():
            return store.objects.contains(o, key_range)

    def __iter__(self):
        return iter(store.objects.iter(direction=direction, range=key_range))

    def to_list(self) -> list[T]:
        return list(store.objects.iter(direction=direction, range=key_range))

    def to_array(self) -> object:
        return tuple(store.objects.iter(direction=direction, range=key_range))

    def remove(self, o: object) -> bool:
        with lock.write_lock():
            return store.objects.remove(o, key_range)

    def contains_all(self, c: Collection[object]) -> bool:
        with lock.read_lock():
            return store.objects.contains_all(c, key_range)

    def remove_all(self, c: Collection[object]) -> bool:
        with lock.write_lock():
            return store.objects.remove_all(c, key_range)

    def retain_all(self, c: Collection[object]) -> None:
        store.objects.retain(c, key_range)

    def clear(self) -> None:
        store.delete_keys(key_range)
```
Note that I've used the `range` module from Python's standard library to represent a range of long integers.