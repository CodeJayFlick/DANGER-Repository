Here is the translation of the Java interface into a Python class:

```Python
class DbgModelTargetProcessContainer:
    def __init__(self):
        pass

    def get_target_process(self, id: 'DebugProcessId') -> 'DbgModelTargetProcess':
        # implement this method
        raise NotImplementedError("Method not implemented")

    def get_target_process(self, process: 'DbgProcess') -> 'DbgModelTargetProcess':
        # implement this method
        raise NotImplementedError("Method not implemented")
```

Note that in Python, we don't have a direct equivalent of Java interfaces. Instead, we can use abstract classes or protocols (in the context of type hints). In this case, I've used an abstract class with unimplemented methods to represent the interface.

The `DebugProcessId` and `DbgModelTargetProcess` types are not defined in your code snippet, so you would need to define them elsewhere.