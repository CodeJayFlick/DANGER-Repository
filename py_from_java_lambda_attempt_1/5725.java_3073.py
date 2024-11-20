Here is the equivalent Python code:

```Python
import threading
import logging

class GhidraThreadGroup:
    def __init__(self):
        self.thread_group = threading.current_thread().name + "Ghidra"
        super().__init__()

    def uncaught_exception(self, t, e):
        self.handle_uncaught_exception(e)

    @staticmethod
    def handle_uncaught_exception(t):
        if isinstance(t, DomainObjectException):
            t = t.__cause__
        elif isinstance(t, TerminatedTransactionException):
            logging.error("Terminated Transaction", exc_info=True)
            print(f"Transaction has been terminated! All open transactions must be closed before a new transaction will be allowed. Try cancelling all long running tasks.")
        elif isinstance(t, DomainObjectLockedException):
            logging.error("Domain Object Locked Exception", exc_info=True)
            print(f"No modifications are permitted until the locking process has completed: {t.__str__()}")
        else:
            from exceptions import SwingExceptionHandler
            SwingExceptionHandler.handle_uncaught_exception(t)

class TerminatedTransactionException(Exception): pass

class DomainObjectLockedException(Exception): pass

# Usage example:

if __name__ == "__main__":
    try:
        # Your code here...
        raise TerminatedTransactionException("Terminated Transaction")
    except Exception as e:
        GhidraThreadGroup().handle_uncaught_exception(e)
```

Please note that Python does not have a direct equivalent to Java's `Thread` class. The above Python code uses the built-in `threading` module, which provides support for threading in Python.

Also, there is no direct equivalent to Java's `Msg.showError()` method in Python. Instead, we use Python's built-in logging and print functions to handle error messages.