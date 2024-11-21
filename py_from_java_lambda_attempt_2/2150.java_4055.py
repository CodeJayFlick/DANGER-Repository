Here is the translation of the given Java code into equivalent Python:

```Python
class DebuggerIgnorableException(Exception):
    def __init__(self, message: str = None, cause: Exception = None) -> None:
        super().__init__()
        if message:
            self.message = message
        else:
            self.message = "Debugger Ignorable Exception"
        
        self.cause = cause

    @classmethod
    def is_ignorable(cls, ex: Exception) -> bool:
        return isinstance(AsyncUtils.unwrap_exception(ex), cls)

class AsyncUtils:
    @staticmethod
    def unwrap_exception(ex: Exception) -> Exception:
        # This method should be implemented based on the actual implementation in Java.
        pass

# Usage example:

try:
    raise DebuggerIgnorableException("This is a test exception", None)
except DebuggerIgnorableException as e:
    if AsyncUtils.is_ignorable(e):
        print(f"Ignoring {e.message}")
```

Please note that this translation assumes the existence of an `AsyncUtils` class with an `unwrap_exception` method, which should be implemented based on the actual implementation in Java.