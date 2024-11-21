Here is the translation of the Java code to Python:

```
class DebuggerObjectModelWithMemory:
    def get_memory(self, target: 'TargetObject', address: 'Address', length: int) -> 'TargetMemory':
        pass
```

Note that I've used type hints for the method parameters and return value. This is a common practice in modern Python code to provide documentation and help with static analysis tools.

Also, since this is an interface definition (i.e., it's not meant to be instantiated), I didn't implement any actual logic inside the `get_memory` method.