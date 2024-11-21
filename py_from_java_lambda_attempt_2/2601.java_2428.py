Here's a translation of the given Java interface into equivalent Python:

```Python
class TraceStackReference:
    def get_stack_offset(self):
        return self.get_to_address().get_offset()

    def is_stack_reference(self):
        return True


from abc import ABC, abstractmethod

class StackReference(ABC):
    @abstractmethod
    def get_offset(self) -> int:
        pass


class TraceReference:
    def __init__(self):
        pass

    def get_to_address(self):
        # Assuming this method returns an object with a 'get_offset' method.
        return self  # For simplicity, I'm returning the same instance here.

```

Please note that Python does not have direct equivalent of Java's interface or abstract classes. However, we can achieve similar functionality using inheritance and polymorphism in Python.