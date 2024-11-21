import io

class NativeString:
    def __init__(self):
        self.pointer = None

    @classmethod
    def of(cls, string: str, encoding='utf-8') -> 'NativeString':
        data = string.encode(encoding)
        if cls._pool is not None and len(data) + 1 <= cls._pool.max_size:
            array = cls._pool.acquire()
            if array.pointer.size() >= len(data):
                array.set_data(data)
                return array
        return NativeString()

    def recycle(self):
        self._pool.recycle(self)

    @property
    def pointer(self):
        return self._pointer

    @pointer.setter
    def set_pointer(self, value):
        self._pointer = value


class ObjectPool:
    def __init__(self, max_size=None):
        if max_size is None:
            max_size = 1024 * 1024
        self.max_size = max_size
        self.pool = []

    @classmethod
    def acquire(cls) -> 'NativeString':
        if cls._pool is not None and len(cls._pool.pool) > 0:
            return NativeString()
        else:
            return None

    @classmethod
    def recycle(cls, obj):
        if cls._pool is not None:
            cls._pool.pool.append(obj)
