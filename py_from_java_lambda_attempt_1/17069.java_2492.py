Here is the translation of the Java code to Python:
```
class BatchProcessException(Exception):
    def __init__(self, failing_status):
        super().__init__("Batch process failed: " + str(failing_status))
        self.failing_status = failing_status

    @property
    def failing_status(self):
        return self._failing_status

batch_process_exception = lambda failing_status: BatchProcessException(failing_status)
```
Note that I've used the built-in `Exception` class in Python as a base class for our custom exception, and implemented the same constructor and property methods. The `lambda` function is just an equivalent way to define a simple factory method in Python.

Also, note that there's no direct equivalent of Java's `TSStatus[]` array type in Python, so I've simply used a list (`failing_status`) instead.