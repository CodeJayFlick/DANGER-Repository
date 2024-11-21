Here is the translation of the Java code to Python:

```Python
import sys
from threading import Thread
from traceback import format_exception

class SwingExceptionHandler:
    def handle(self, t):
        self.handle_uncaught_exception(t)

    @staticmethod
    def register_handler():
        try:
            thread = Thread(target=lambda: None)
            thread.setDaemon(True)  # Set the daemon flag to True.
            thread.start()
            thread.join()  # Wait for the thread to finish.

            old_handler = sys.excepthook

            def new_handler(t, value, tb):
                SwingExceptionHandler().handle_uncaught_exception(value)

            sys.excepthook = new_handler
        except Exception as e:
            print(f"Error: {e}")

    @staticmethod
    def handle_uncaught_exception(t):
        if isinstance(t, InvocationTargetException):
            t = t.cause

        if isinstance(t, ThreadDeath):
            return

        if isinstance(t, ConnectException):
            return

        if isinstance(t, ClosedException):
            return

        details = ""
        if isinstance(t, MemoryError):
            runtime = sys.getsizeof(0)
            details += f"\nMemory: free={runtime} max={sys.maxsize} total={sys.totalmem()}"
        else:
            message = str(t)
            if message is not None:
                details += f"\n{t.__class__.__name__} - {message}"

        try:
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.critical(None, "Error", f"Uncaught Exception! {details}", t)
        except ImportError as e:
            print(f"Error: {e}")

    def uncaught_exception(self, thread, exception):
        self.handle_uncaught_exception(exception)

# Usage example:
SwingExceptionHandler.register_handler()
```

Please note that Python does not have a direct equivalent to Java's Swing event dispatch thread. The above code is an attempt to mimic the behavior of the original Java code in Python.

Also, this translation assumes you are using PyQt5 for GUI operations (like showing error messages). If you're not using PyQt5 or want to use another library, you'll need to modify the `handle_uncaught_exception` method accordingly.