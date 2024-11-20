Here is the translation of the Java code into Python:

```Python
class SpacerFieldLocation:
    def __init__(self, program: 'Program', addr: int, component_path: list[int], char_offset: int, text: str):
        super().__init__(program=program, addr=addr, component_path=component_path, 0, 0, char_offset)
        self.text = text

    def __str__(self) -> str:
        return f"{super().__str__()}, Spacer text={self.text}"

class Program:
    pass
```

Note that Python does not have direct equivalent of Java's `Address` class. I've replaced it with an integer in the translation.

Also, note that Python doesn't support generic types like Java does. The type hinting is used to indicate what kind of object a variable or parameter should be.