Here is the translation of the given Java code into equivalent Python:

```Python
from concurrent.futures import Future

class GdbModelSelectableObject:
    def __init__(self):
        pass

    async def set_active(self) -> Future[None]:
        return await Future(None)
```

Note that in this translation, we are using `async` and `await` to create a coroutine for the `set_active` method. This is because Python does not have direct equivalent of Java's CompletableFuture class.