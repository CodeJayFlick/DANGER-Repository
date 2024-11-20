Here is the equivalent Python code:

```Python
class TsfHadoopException(Exception):
    def __init__(self):
        super().__init__()

    def __init__(self, message: str = None, cause=None, enable_suppression=False, writable_stack_trace=True):
        if message:
            super().__init__(message)
        else:
            super().__init__()
        self.cause = cause
        self.enable_suppression = enable_suppression
        self.writable_stack_trace = writable_stack_trace

    def __init__(self, message: str):
        super().__init__(message)

    def __init__(self, cause: Exception):
        super().__init__(cause)
```

Note that Python does not have a direct equivalent to Java's `serialVersionUID`. Also, the default values for parameters in the constructors are different from those in Java.