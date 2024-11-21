Here is a translation of the Java interface into equivalent Python:

```Python
class TargetModuleContainer:
    SUPPORTS_SYNTHETIC_MODULES_ATTRIBUTE_NAME = "supports_synthetic_modules"

    def supports_synthetic_modules(self):
        return self.get_typed_attribute_now_by_name(SUPPORTS_SYNTHETIC_MODULES_ATTRIBUTE_NAME, bool)

    async def add_synthentic_module(self, name: str) -> CompletableFuture:
        raise NotImplementedError

class CompletableFuture:
    pass
```

Note that Python does not have a direct equivalent to Java's `CompletableFuture`. The above code uses the built-in `async` and `await` keywords for asynchronous programming.