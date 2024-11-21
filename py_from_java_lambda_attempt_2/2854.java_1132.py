Here is the translation of the Java code to Python:
```
import threading

class LockHold:
    def __init__(self, lock):
        self.lock = lock

    @staticmethod
    def lock(lock):
        hold = LockHold(lock)
        hold.lock.acquire()
        return hold

    def close(self):
        self.lock.release()

# Example usage:
lock = threading.Lock()
hold = LockHold.lock(lock)

try:
    # do something with the locked resource
except Exception as e:
    print(f"Error: {e}")
finally:
    hold.close()  # release the lock when done
```
Note that Python's `threading` module provides a similar concept to Java's `Lock` class, which is used in this translation. The `acquire()` and `release()` methods are equivalent to Java's `lock().unlock()` calls.