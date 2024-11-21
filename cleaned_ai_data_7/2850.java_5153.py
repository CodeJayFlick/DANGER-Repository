import threading

class GhidraLockHold:
    @staticmethod
    def lock(lock):
        hold = GhidraLockHold(lock)
        hold.lock.acquire()
        return hold

    def __init__(self, lock):
        self.lock = lock

    def close(self):
        self.lock.release()

# Example usage:

lock = threading.Lock()  # Create a Lock object
hold = GhidraLockHold.lock(lock)  # Acquire the lock and create an instance of GhidraLockHold
try:
    pass  # Use hold here...
finally:
    hold.close()  # Release the lock when you're done with it.
