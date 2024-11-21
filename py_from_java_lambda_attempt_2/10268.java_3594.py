Here is the translation of the Java code to Python:
```python
import os

class ChannelLocker:
    CHANNEL_LOCK_TYPE = "Channel Lock"

    def __init__(self, lock_file):
        super().__init__(lock_file)

    def get_lock_type(self):
        return self.CHANNEL_LOCK_TYPE

    def lock(self):
        if self.can_lock():
            return self.create_lock_file()
        return False

    def can_lock(self):
        if not hasattr(self, 'existing_lock_type') or self.existing_lock_type is None:
            return True
        return self.can_channel_lock()

    def can_channel_lock(self):
        if self.CHANNEL_LOCK_TYPE != self.existing_lock_type:
            return False
        return self.is_channel_lock_available()

    def is_channel_lock_available(self):
        test_channel_lock = FileChannelLock(lock_file)
        did_lock = test_channel_lock.lock()
        test_channel_lock.release()
        return did_lock

    def create_lock_file(self):
        if not super().create_lock_file():
            return False
        self.channel_lock = FileChannelLock(lock_file)
        self.is_locked = self.channel_lock.lock()
        return self.is_locked

    def release(self):
        if hasattr(self, 'channel_lock') and self.channel_lock is not None:
            self.channel_lock.release()
        super().release()

class FileChannelLock:
    def __init__(self, lock_file):
        pass  # implement me!

    def lock(self):
        raise NotImplementedError("Implement this method!")

    def release(self):
        raise NotImplementedError("Implement this method!")
```
Note that I've kept the `FileChannelLock` class abstract and didn't provide any implementation for it. You'll need to fill in the blanks with your own code.

Also, Python doesn't have a direct equivalent of Java's `@Override` annotation, so I omitted those.