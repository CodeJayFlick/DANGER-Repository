Here is the equivalent Python code:

```Python
import os
import fcntl


class FileChannelLock:
    def __init__(self, lock_file):
        self.lock_file = lock_file + "~"
        self.is_locked = False

    def lock(self):
        try:
            with open(self.lock_file, 'a') as out:
                fc = out.fileno()
                fl = fcntl.flock(fc)
                self.is_locked = True
                if not self.is_locked:
                    return False
                else:
                    return True
        except IOError:
            return False

    def release(self):
        try:
            with open(self.lock_file, 'a') as out:
                fc = out.fileno()
                fcntl.flock(fc, fcntl.LOCK_UN)
        except IOError:
            pass
        if self.is_locked:
            os.remove(self.lock_file)


# Example usage:

lock_file = "path_to_your_lock_file.txt"
lock = FileChannelLock(lock_file)

if lock.lock():
    print("Locked successfully")
else:
    print("Failed to lock")

lock.release()
```

Please note that Python's `flock` function is used for locking, which is different from Java's `FileChannel.tryLock()`. Also, the file mode in Python (`'a'`) means "append", but it can be changed according to your needs.