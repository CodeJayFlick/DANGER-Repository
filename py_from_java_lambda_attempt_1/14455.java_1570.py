Here is the translation of the Java code to Python:

```Python
class Message:
    def __init__(self):
        self.type = None
        self.content = ""

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        self._type = value

    @property
    def content(self):
        return self._content

    @content.setter
    def content(self, value):
        self._content = value

    def __eq__(self, other):
        if not isinstance(other, Message):
            return False
        return (self.type == other.type and 
                self.content == other.content)

    def __hash__(self):
        return hash((self.type, self.content))
```

Note that Python does not have direct equivalents to Java's `@Setter`, `@Getter`, `@EqualsAndHashCode` or `@AllArgsConstructor`. Instead, we use the following:

- The constructor (`__init__`) is used to initialize the object.
- Properties are implemented using getter and setter methods (e.g., `type.setter`).
- Equality comparison is handled by implementing the `__eq__` method. In this case, it checks if both objects have the same type and content.
- Hashing is implemented in the `__hash__` method based on the object's properties.