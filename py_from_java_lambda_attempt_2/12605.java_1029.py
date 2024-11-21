Here is the translation of the given Java interface into a Python class:

```Python
class MutableMemBuffer:
    def __init__(self):
        pass

    def advance(self, displacement: int) -> None:
        # Add your implementation here to handle AddressOverflowException
        raise NotImplementedError("advance method not implemented")

    def set_position(self, addr: 'Address') -> None:
        # Add your implementation here for setting the position of the buffer
        raise NotImplementedError("set_position method not implemented")

    def clone(self) -> 'MutableMemBuffer':
        # Implement cloning logic here
        return self.__class__()
```

Please note that this is a direct translation and does not include any actual functionality. You would need to implement these methods according to your specific requirements.

Also, I used the `raise NotImplementedError` statement in each method as it's common practice when implementing an interface or abstract class in Python. This indicates that the method needs to be implemented by subclasses.