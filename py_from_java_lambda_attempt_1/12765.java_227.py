Here is the translation of the Java code to Python:
```
class FunctionCallingConventionFieldLocation:
    def __init__(self, program: 'Program', location_addr: int, function_addr: int,
                 char_offset: int, signature: str):
        super().__init__(program, location_addr, function_addr, char_offset, signature)

    def __init__(self):  # Default constructor needed for restoring
        pass

class Program:
    pass

class Address:
    pass

class String:
    pass
```
Note that I've used Python's type hinting system to indicate the types of the variables and method parameters. This is not strictly necessary, but it can help with code readability and maintainability.

Also, I've kept the `Program`, `Address`, and `String` classes as simple placeholders, since they are not defined in the original Java code. In a real-world implementation, you would need to define these classes or use existing ones that provide similar functionality.