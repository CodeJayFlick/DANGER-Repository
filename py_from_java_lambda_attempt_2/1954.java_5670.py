Here is the translation of the Java interface `GadpClientTargetDetachable` to a Python class:

```python
import asyncio

class GadpClientTargetDetachable:
    def __init__(self):
        pass

    async def detach(self) -> None:
        await self.get_delegate().assert_valid()
        reply = await self.get_model().send_checked(
            Gadp.DetachRequest.newBuilder().set_path(GadpValueUtils.make_path(self.get_path())).build(),
            Gadp.DetachReply.getDefaultInstance())
```

Note that Python does not have direct equivalents to Java's interfaces, classes, or methods. Instead, we define a class `GadpClientTargetDetachable` with an asynchronous method `detach`. The method uses the `asyncio` library for asynchronous programming.

The rest of the code is translated as follows:

* `@Override`: Not needed in Python.
* `default CompletableFuture< Void > detach() { ... }`: Translated to a class method `detach()` that returns `None`.
* `getDelegate().assertValid();`: Translated to calling an instance method `assert_valid` on the delegate object, which is assumed to be stored as an attribute of this class.
* `return getModel().sendChecked( ... ).thenApply(rep -> null);`: Translated to using Python's asynchronous programming features with `asyncio`. The `getModel()` and `send_checked()` methods are assumed to return coroutine objects that can be awaited.