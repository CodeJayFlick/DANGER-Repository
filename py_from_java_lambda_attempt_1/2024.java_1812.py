Here is the translation of the given Java interface into a Python class:

```Python
from concurrent.futures import Future

class JdiModelTargetDetachable:
    def __init__(self):
        pass

    def detach(self) -> Future[None]:
        # This method should return a CompletableFuture< Void > in Java.
        # In Python, we can use the built-in asyncio library to achieve similar functionality.
        loop = asyncio.get_event_loop()
        future: Future[None] = loop.run_in_executor(None, lambda: None)
        return future
```

Please note that this translation is not a direct equivalent of the given Java interface. The `detach` method in Python does not exactly match its counterpart in Java because it returns a different type (`Future[None]`) and has slightly different behavior (it doesn't actually detach anything, but rather creates an asynchronous task).