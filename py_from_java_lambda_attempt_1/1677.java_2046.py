Here is the translation of the given Java interface into a Python class:

```Python
from typing import Dict, Collection, Any

class LldbModelTargetRegisterBank:
    def __init__(self):
        self.cached_registers = {}

    def get_target_register(self, register: bytes) -> 'LldbModelTargetRegister':
        # This method is not implemented in the Java code. It's assumed to be some kind of lookup.
        pass

    def thread_state_changed_specific(self, state: str, reason: Any):
        self.read_registers_named(list(self.cached_registers.keys()))

    async def read_registers_named(self, names: Collection[str]) -> Dict[str, bytes]:
        # This method is not implemented in the Java code. It's assumed to be some kind of asynchronous lookup.
        pass

    async def write_registers_named(self, values: Dict[str, bytes]) -> Any:
        # This method is not implemented in the Java code. It's assumed to be some kind of asynchronous update.
        pass

    def get_cached_registers(self) -> Dict[str, bytes]:
        return self.get_values()

    def get_values(self) -> Dict[str, bytes]:
        result = {}
        for key, value in self.cached_attributes().items():
            if isinstance(value, LldbModelTargetRegister):
                reg = value
                bytes_ = reg.to_bytes()
                result[key] = bytes_
        return result

class LldbModelTargetRegister:
    def __init__(self):
        pass

    def to_bytes(self) -> bytes:
        # This method is not implemented in the Java code. It's assumed to be some kind of conversion.
        pass
```

Note that this translation assumes a few things about the original Java interface:

- The `LldbModelTargetRegister` class has been translated into a Python class with an equivalent constructor and a single method (`to_bytes`) which is not implemented in the given code. In reality, it might be some kind of wrapper around another object.
- The `getCachedAttributes()` method returns a dictionary-like object that can be iterated over using `.items()`. This assumes that this method has been translated into Python and its return value can be used as expected.

Also note that the translation does not include any actual implementation for methods like `get_target_register`, `read_registers_named` or `write_registers_named` because these were left unimplemented in the original Java code.