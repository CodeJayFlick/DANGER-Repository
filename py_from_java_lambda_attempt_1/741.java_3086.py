Here is the translation of the given Java code into equivalent Python:

```Python
from concurrent.futures import Future

class DbgModelTargetDetachable:
    def __init__(self):
        pass

    def detach(self) -> Future[None]:
        process = self.get_manager().get_current_process()
        return self.get_model().gate_future(process.detach())

    def get_manager(self):
        # This method should be implemented in the subclass
        raise NotImplementedError("Method not implemented")

    def get_model(self):
        # This method should be implemented in the subclass
        raise NotImplementedError("Method not implemented")
```

Note that Python does not have direct equivalents for Java's interfaces, classes and methods. Instead, we define a class `DbgModelTargetDetachable` with abstract methods (`get_manager`, `get_model`) which are intended to be overridden by any concrete subclasses.