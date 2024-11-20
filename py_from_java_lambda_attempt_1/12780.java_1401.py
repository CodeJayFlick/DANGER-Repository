Here is the translation of the given Java code into Python:

```Python
class FunctionThunkFieldLocation:
    def __init__(self, program: 'Program', location_addr: int, function_addr: int, char_offset: int, signature: str):
        super().__init__(program, location_addr, function_addr, char_offset, signature)

    def __init__(self):  # Default constructor needed for restoring a program location from XML
        pass

class Program:
    pass

class Address:
    pass

class String:
    pass
```

Please note that Python does not have direct equivalent of Java's `package`, `import` statements. Also, the classes in this code are just placeholders and you would need to define them according to your actual requirements.

Also, Python doesn't support checked exceptions like Java does with its `throws` keyword.