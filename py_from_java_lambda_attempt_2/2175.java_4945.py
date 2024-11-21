Here is the translation of the given Java code into equivalent Python:

```Python
from concurrent.futures import Future

class TargetActiveScope:
    def __init__(self):
        pass

    @property
    def debugger_target_object_iface(self):
        return "ActiveScope"

    async def request_activation(self, obj: 'TargetObject') -> Future[None]:
        # Implement the logic for setting the given object as the target's active object
        # For now, just simulate a future that completes successfully.
        awaitable = lambda: None  # Replace with actual implementation
        return awaitable

class TargetObject:
    pass
```

Please note that Python does not have direct equivalent of Java interfaces. However, we can achieve similar functionality using abstract classes or protocols (in Python's type hinting). In this translation, I've used a simple class `TargetActiveScope` to represent the interface in Python.

The method `request_activation` is designed as an asynchronous function that returns a future-like object (`Future[None]`) which completes successfully. You would need to replace the lambda function with actual implementation of setting the given object as the target's active object.