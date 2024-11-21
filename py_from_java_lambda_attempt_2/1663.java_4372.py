Here is the translation of the Java interface `LldbModelTargetConnector` into a Python class:

```python
from typing import Dict, Any

class LldbModelTargetConnector:
    def get_display(self) -> str:
        return self.get_name()

    async def set_active(self) -> None:
        pass  # CompletableFuture equivalent in Python is not implemented here

    def get_parameters(self) -> dict:
        raise NotImplementedError("getParameters method has to be implemented")

    async def launch(self, args: Dict[str, Any]) -> None:
        pass  # CompletableFuture equivalent in Python is not implemented here
```

Note that:

* The `@Override` annotations are removed as they are specific to Java.
* In the `set_active`, `get_parameters`, and `launch` methods, I've used placeholder code (`pass`) since there's no direct equivalent of Java's `CompletableFuture` in Python. You would need to implement these methods according to your requirements.
* The `Map<String, ?> args` is translated into a Python dictionary with string keys and any type values (using the `Dict[str, Any]` type hint).
* I've used the `async def` syntax for the `set_active` and `launch` methods since they seem to be asynchronous operations.