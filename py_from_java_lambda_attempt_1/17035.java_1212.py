Here is the translation of the Java code to Python:

```Python
import logging

class TsFileResource:
    def __init__(self):
        self.prev = None
        self.next = None


class TsFileResourceList(list):
    def __init__(self):
        super().__init__()
        self.lock = ReentrantReadWriteLock()

    def read_lock(self):
        self.lock.read_lock().acquire()

    def read_unlock(self):
        self.lock.read_lock().release()

    def write_lock(self):
        self.lock.write_lock().acquire()

    def try_write_lock(self, timeout=0.1):
        return self.lock.write_lock().try_lock(timeout)

    def write_lock_with_timeout(self, timeout):
        if not self.try_write_lock(timeout):
            raise WriteLockFailedException(f"Cannot get write lock in {timeout} seconds")

    def write_unlock(self):
        self.lock.write_lock().release()

    def insert_before(self, node, new_node):
        with self.write_lock():
            new_node.prev = node
            if node is None:
                self.append(new_node)
            else:
                node.prev.next = new_node
            self.count += 1

    def insert_after(self, node, new_node):
        with self.write_lock():
            new_node.prev = node
            new_node.next = node.next
            if node.next is None:
                self.append(new_node)
            else:
                node.next.prev = new_node
            self.count += 1

    @property
    def size(self):
        return len(self)

    @property
    def empty(self):
        return not bool(len(self))

    def contains(self, o):
        with self.read_lock():
            if isinstance(o, TsFileResource):
                for node in self:
                    if node == o:
                        return True
            return False

    def iterator(self):
        return iter(self)

    def reverse_iterator(self):
        return reversed(list(self))

    def add(self, new_node):
        with self.write_lock():
            if isinstance(new_node.prev, TsFileResource) or isinstance(new_node.next, TsFileResource):
                return False
            elif len(self) == 0:
                super().append(new_node)
            else:
                self.insert_after(tail=self[-1], node=new_node)
            return True

    def remove(self, o):
        with self.write_lock():
            if isinstance(o, TsFileResource):
                for i in range(len(self)):
                    if self[i] == o:
                        del self[i]
                        break
            else:
                raise ValueError("Invalid object")

    @property
    def count(self):
        return len(self)

    def clear(self):
        with self.write_lock():
            super().clear()

    def get(self, index):
        for i in range(len(self)):
            if i == index:
                return self[i]
        raise IndexError(f"Index {index} out of bounds")

    @property
    def header(self):
        return None

    @property
    def tail(self):
        return None


class WriteLockFailedException(Exception):
    pass


class ReentrantReadWriteLock:
    def __init__(self):
        self.read_lock = threading.Lock()
        self.write_lock = threading.Lock()

    def read_lock(self, timeout=0.1):
        if not self.read_lock.acquire(timeout=int(timeout*1000)):
            raise WriteLockFailedException(f"Cannot get read lock in {timeout} seconds")

    def write_lock(self, timeout=0.1):
        if not self.write_lock.acquire(timeout=int(timeout*1000), wait_for=False):
            raise WriteLockFailedException(f"Cannot get write lock in {timeout} seconds")

    def try_read_lock(self, timeout=0.1):
        return self.read_lock.acquire(timeout=int(timeout*1000))

    def read_unlock(self):
        self.read_lock.release()

    def try_write_lock(self, timeout=0.1):
        return self.write_lock.acquire(timeout=int(timeout*1000), wait_for=False)

    def write_unlock(self):
        self.write_lock.release()
```

This Python code does not exactly match the Java code provided as it doesn't include all of the methods and classes from the original Java code, but rather translates the main parts.