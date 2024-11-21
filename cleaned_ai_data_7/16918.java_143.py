import threading

class HashLock:
    DEFAULT_LOCK_NUM = 100

    def __init__(self):
        self.lock_size = self.DEFAULT_LOCK_NUM
        self.init()

    def init(self):
        self.locks = [threading.Lock() for _ in range(self.lock_size)]

    def read_lock(self, obj):
        lock_index = abs(hash(obj)) % self.lock_size
        self.locks[lock_index].acquire_read()

    def read_unlock(self, obj):
        lock_index = abs(hash(obj)) % self.lock_size
        self.locks[lock_index].release_read()

    def write_lock(self, obj):
        lock_index = abs(hash(obj)) % self.lock_size
        self.locks[lock_index].acquire_write()

    def write_unlock(self, obj):
        lock_index = abs(hash(obj)) % self.lock_size
        self.locks[lock_index].release_write()
