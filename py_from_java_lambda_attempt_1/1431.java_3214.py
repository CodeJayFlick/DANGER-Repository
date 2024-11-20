Here is the translation of the given Java code into equivalent Python:

```Python
import os
import threading

class LocalProcessPtySession:
    def __init__(self, process):
        self.process = process
        print(f"local Pty session. PID = {process.pid()}")

    def wait_exited(self):
        try:
            return self.process.wait()
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(f"Error: {e}")
            return None

    def destroy_forcibly(self):
        try:
            self.process.terminate()
        except Exception as e:
            print(f"Error: {e}")

# Example usage:

process = os.popen("your_command_here", "r")
pty_session = LocalProcessPtySession(process)
```

Please note that Python does not have a direct equivalent to Java's `Process` class. Instead, we use the built-in `os.popen()` function or the `subprocess` module to run external commands and capture their output.

Also, Python does not support multithreading in the same way as Java (Java has true threads that can be used for concurrent execution of tasks). In Python, you would typically use processes instead of threads if you need concurrency.