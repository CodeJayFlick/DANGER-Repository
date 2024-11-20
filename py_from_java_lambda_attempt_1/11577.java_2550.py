Here is the translation of the Java code to Python:
```
class UnimplementedInstructionException(Exception):
    def __init__(self, address):
        super().__init__(f"Unimplemented instruction, PC={address}")
        self.address = address

    @property
    def get_instruction_address(self):
        return self.address
```
Note that I've used the built-in `Exception` class in Python as a base class for our custom exception. In Java, you would use `extends LowlevelError`, but in Python, we don't need to specify an explicit parent class.

I've also replaced the `super()` call with the equivalent syntax using the `__init__` method of the built-in `Exception` class. The rest of the code is similar, just translated from Java to Python.