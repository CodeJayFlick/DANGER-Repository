Here is a translation of the Java interface into equivalent Python code:

```Python
from typing import Callable, Any

class LldbModelTargetActiveScope:
    def __init__(self):
        pass

    async def request_activation(self, obj: 'LldbModelTargetObject') -> None:
        return await self.get_model().gate_future(self.get_manager().request_activation(self, obj))

    async def do_request_activation(self, obj: 'LldbModelTargetObject') -> None:
        if self.get_manager().is_waiting():
            return

        self.get_model().assert_mine('LldbModelTargetObject', obj)
        if not PathUtils.is_ancestor(self.get_path(), obj.get_path()):
            raise DebuggerIllegalArgumentException("Can only focus a successor of the scope")

        cur = obj
        while cur is not None:
            if isinstance(cur, LldbModelSelectableObject):
                sel = cast(LldbModelSelectableObject, cur)
                return await sel.set_active()
            elif isinstance(cur, LlldbModelTargetObject):
                def_ = cast(LlldbModelTargetObject, cur)
                cur = def_.get_parent()
                continue
            raise AssertionError()

    async def get_model(self) -> Any:
        pass

    async def get_manager(self) -> Any:
        pass

class DebuggerIllegalArgumentException(Exception):
    pass
```

Please note that Python does not have direct equivalent of Java's interface, but we can achieve similar functionality using abstract classes or protocols. Also, the `CompletableFuture` in Java is replaced with asynchronous functions (`async/await`) in Python.

The above code assumes you are using type hints and casting to ensure correct types for variables.