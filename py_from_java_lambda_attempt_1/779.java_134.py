Here is the translation of the Java interface into a Python class:

```Python
class DbgModelTargetRegisterContainerAndBank:
    def __init__(self):
        pass

    def get_target_register(self, register: 'DbgRegister') -> 'DbgModelTargetRegister':
        # implement this method as needed
        pass


from abc import ABC, abstractmethod

class DbgModelTargetObject(ABC):
    @abstractmethod
    def __str__(self) -> str:
        pass


class DbgModelTargetRegister(ABC):
    @abstractmethod
    def get_register(self) -> 'DbgRegister':
        pass


# These are placeholder classes for now, you would need to implement them as needed.
```

Please note that Python does not have direct equivalent of Java's interface. But we can achieve similar functionality using abstract base class (ABC).