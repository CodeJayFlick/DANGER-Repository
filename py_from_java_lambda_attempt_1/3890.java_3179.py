Here is the translation of the given Java interface into a Python class:

```Python
class StackDepthChangeListener:
    def __init__(self):
        pass

    def actionPerformed(self, event: 'StackDepthChangeEvent'):
        # Your action performed code here
        pass


from abc import ABC, abstractmethod


class EventListener(ABC):
    @abstractmethod
    def process_event(self, event):
        pass


class StackDepthChangeEvent:
    pass
```

Note that Python does not have a direct equivalent to Java's interface. Instead, we can use an abstract base class (ABC) with abstract methods as shown above.