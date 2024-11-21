Here is the translation of the Java code to Python:
```
import json

class FunctionTagRowObject:
    def __init__(self, tag: 'FunctionTag', count: int):
        self.tag = tag
        self.count = count

    @property
    def tag(self) -> 'FunctionTag':
        return self._tag

    @tag.setter
    def tag(self, value: 'FunctionTag'):
        self._tag = value

    @property
    def count(self) -> int:
        return self._count

    @count.setter
    def count(self, value: int):
        self._count = value

    def get_name(self) -> str:
        return self.tag.name()

    def is_immutable(self) -> bool:
        return isinstance(self.tag, InMemoryFunctionTag)

    def get_comment(self) -> str:
        return self.tag.comment()

    def __str__(self):
        return f"{type(self).__name__}\n{json.dumps(self.__dict__, indent=4)}"

class FunctionTag:
    # assuming this class exists in the original Java code
    pass

InMemoryFunctionTag = object  # placeholder for the actual InMemoryFunctionTag class
```
Note that I had to make some assumptions about the `FunctionTag` and `InMemoryFunctionTag` classes, as they were not provided. You will need to define these classes or replace them with equivalent Python constructs.

Also, in Python, we don't have a direct equivalent of Java's `@Override` annotation, so I omitted it from the code.