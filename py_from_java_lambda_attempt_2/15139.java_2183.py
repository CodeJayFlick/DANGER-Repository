Here is the translation of the Java code to Python:

```Python
class Student:
    def __init__(self, id: int, name: str, address: str):
        self.id = id
        self.name = name
        self.address = address

    @property
    def id(self) -> int:
        return self._id

    @property
    def name(self) -> str:
        return self._name

    @property
    def address(self) -> str:
        return self._address
```

Note that Python does not have a direct equivalent to Java's `@Getter` and `@RequiredArgsConstructor`. The above code uses Python's property decorator (`@property`) to achieve similar functionality.