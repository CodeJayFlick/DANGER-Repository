Here is the translation of the given Java code into equivalent Python:

```Python
class Modification:
    def __init__(self, type: str, partial_path: dict, file_offset: int):
        self.type = type
        self.partial_path = partial_path
        self.file_offset = file_offset

    @property
    def path(self) -> dict:
        return self.partial_path

    @path.setter
    def set_path(self, value: dict):
        self.partial_path = value

    @property
    def device(self) -> str:
        if 'device' in self.partial_path:
            return self.partial_path['device']
        else:
            return None

    @property
    def measurement(self) -> str:
        if 'measurement' in self.partial_path:
            return self.partial_path['measurement']
        else:
            return None

    @property
    def file_offset(self) -> int:
        return self.file_offset

    @file_offset.setter
    def set_file_offset(self, value: int):
        self.file_offset = value

    def __eq__(self, other):
        if isinstance(other, Modification):
            return (self.type == other.type and 
                    self.partial_path == other.partial_path and 
                    self.file_offset == other.file_offset)
        else:
            return False

    def __hash__(self) -> int:
        return hash((self.type, tuple(self.partial_path.items()), self.file_offset))

class Type:
    DELETION = 'DELETION'
```

Note that Python does not have an equivalent to Java's `enum` type. Instead, we can define a class with static attributes for the possible types of modifications.

Also note that in Python, it is common practice to use properties (i.e., getter and setter methods) instead of direct attribute access. This allows you to add validation or other logic when setting an attribute.