Here is the translation of the given Java code into Python:

```Python
class ThunkedFunctionFieldLocation:
    def __init__(self, program: 'Program', location_addr: int, function_addr: int, thunked_function_addr: int, char_offset: int):
        super().__init__(program=program, location_addr=location_addr, function_addr=function_addr, 0, 0, char_offset)
        self.ref_addr = thunked_function_addr

    def __init__(self):  # Default constructor needed for restoring a program location from XML
        pass


class Program:
    pass


class Address:
    pass
```

Please note that Python does not have direct equivalent of Java's `package`, `import` statements. Also, Python classes do not require explicit declaration of constructors like in Java. The above code is the translation of given Java code into Python and it should be used as a starting point for further development.