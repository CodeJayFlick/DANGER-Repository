Here is the translation of the given Java code into Python:

```Python
from enum import Enum

class ContentsType(Enum):
    pass  # You need to define your contents types here


class ContentsIdWithType:
    def __init__(self, contents_id: str, type: ContentsType):
        self.contents_id = contents_id
        self.type = type

    @classmethod
    def of(cls, contents_id: str, type: ContentsType) -> 'ContentsIdWithType':
        return cls(contents_id=contents_id, type=type)
```

Note that in Python, we don't have a direct equivalent to Java's `@Value.Immutable` annotation or the concept of interfaces with default implementations (like Java 8's functional interfaces). We've implemented this using a regular class and an abstract method (`of`) which is not meant to be overridden by subclasses.

Also note that in Python, we don't have a direct equivalent to Java's `byte` type. In Python, you would typically use integers or strings for similar purposes.