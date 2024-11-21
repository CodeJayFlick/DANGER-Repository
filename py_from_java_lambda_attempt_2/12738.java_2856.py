Here is the translation of the Java code into Python:

```Python
class AddressFieldLocation:
    def __init__(self, program: 'Program', addr: 'Address', component_path=None,
                 addr_representation: str = None, char_offset=0):
        super().__init__(program, addr, component_path, 0, 0, char_offset)
        self.addr_representation = addr_representation

    @classmethod
    def default(cls, program: 'Program', addr: 'Address'):
        return cls(program, addr)

    def __str__(self) -> str:
        return f"{super().__str__()}, AddressRep={self.addr_representation}"

    def get_address_representation(self) -> str:
        return self.addr_representation

class Program:
    pass
```

Note that I've used Python's type hinting to indicate the types of variables and function parameters. However, since this is not enforced at runtime in Python (unlike Java), these hints are purely for documentation purposes.

I have also omitted some parts of the code as they were specific to Java framework and did not translate well into Python.