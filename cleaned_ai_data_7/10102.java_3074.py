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
