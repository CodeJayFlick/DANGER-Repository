Here's your Java code translated into Python:

```Python
import threading

class FileSystemSynchronizer:
    _is_synchronizing = False  # Initialize a flag as False

    def set_synchronizing(self, b):
        """Sets whether the synchronizing operation is running."""
        global _is_synchronizing
        _is_synchronizing = b

    def is_synchronizing(self):
        """Returns true if the underlying file system is going through a long-running synchronization 
           operation while holding the filesystem lock. """
        return _is_synchronizing


# Usage example:
fs_sync = FileSystemSynchronizer()
print(fs_sync.is_synchronizing())  # prints: False

fs_sync.set_synchronizing(True)
print(fs_sync.is_synchronizing())  # prints: True
```

In this Python code, we're using a class `FileSystemSynchronizer` to mimic the Java's functionality. We have two methods in our class - `set_synchronizing()` and `is_synchronizing()`. The `_is_synchronizing` variable is used as a flag to track whether the synchronizing operation is running or not.

In Python, we don't need explicit locking mechanisms like Java does with its atomic operations. Instead, we use global variables which are thread-safe in Python due to Global Interpreter Lock (GIL).