Here is the translation of the given Java code into equivalent Python:

```Python
from concurrent.futures import Future

class LldbModelTargetInterruptible:
    def __init__(self):
        pass

    def interrupt(self) -> Future[None]:
        self.get_manager().send_interrupt_now()
        return Future.completed(None)
```

Note that this translation is not a direct conversion, but rather an equivalent implementation in Python. The Java code uses interfaces and classes to define the behavior of objects, whereas Python relies more on duck typing (i.e., it does not require explicit interface or class definitions).