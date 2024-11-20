Here is the translation of the Java interface into Python:

```
class BasicSpaceProvider:
    def __init__(self):
        pass

    # Most processors have a main address bus, on which the bulk
    # of the processor's RAM is mapped. Everything referenced
    # with this address bus should be modeled in pcode with a
    # single address space, referred to as the default space.
    def get_default_space(self):
        pass

    # Pcode represents constant values within an operation as
    # offsets within a special constant address space.
    # (See ConstantSpace)
    def get_constant_space(self):
        pass


# Example usage:
class MyBasicSpaceProvider(BasicSpaceProvider):
    def __init__(self):
        super().__init__()

    def get_default_space(self):
        return "Default Space"

    def get_constant_space(self):
        return "Constant Space"


my_provider = MyBasicSpaceProvider()
print(my_provider.get_default_space())  # Output: Default Space
print(my_provider.get_constant_space())  # Output: Constant Space