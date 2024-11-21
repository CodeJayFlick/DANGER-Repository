Here is the translation of the Java code to Python:
```
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
```
Note that I used the `threading` module to create locks and acquire/release them. The rest of the code is similar to the Java original, with some minor adjustments for Python syntax and semantics.

Also, in Python, we don't need to explicitly specify a lock size or initialize an array of locks like you would do in Java. Instead, I used a list comprehension to create a list of locks when initializing the `HashLock` object.