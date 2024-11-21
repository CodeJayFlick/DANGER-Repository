import collections
from threading import Lock, RLock

class DBCachedObjectStoreValueCollection:
    def __init__(self, store: 'DBCachedObjectStore', err_handler: callable, lock: RLock, direction: str):
        self.store = store
        self.err_handler = err_handler
        self.lock = lock
        self.direction = direction

    @property
    def size(self) -> int:
        return self.store.get_record_count()

    @property
    def is_empty(self) -> bool:
        return self.size == 0

    def contains(self, obj: object) -> bool:
        with self.lock.read_lock():
            return self.store.objects.contains(obj)

    def __iter__(self):
        return iter(self.store.objects.iterate(self.direction))

    def to_list(self) -> list:
        return list(self.store.objects.iterate(self.direction))

    def to_array(self, a: object = None) -> object:
        if not a:
            return self.to_list()
        else:
            return [self.store.objects.get(i) for i in range(self.size)]

    def add(self, e: 'T') -> bool:
        raise NotImplementedError

    def remove(self, obj: object) -> bool:
        with self.lock.write_lock():
            return self.store.objects.remove(obj)

    def contains_all(self, c: collections.abc.Collection) -> bool:
        with self.lock.read_lock():
            return all(i in c for i in self.store.objects)

    def add_all(self, c: collections.abc.Collection) -> bool:
        raise NotImplementedError

    def remove_all(self, c: collections.abc.Collection) -> bool:
        with self.lock.write_lock():
            return all(i not in c for i in self.store.objects)

    def retain_all(self, c: collections.abc.Collection) -> bool:
        return self.store.objects.retain(c)

    def clear(self):
        self.store.delete_all()
