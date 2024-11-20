Here is the translation of the given Java code into equivalent Python:

```Python
class KeyWithType:
    def __init__(self, key: 'Key', contents_id: str, type: int):
        self.key = key
        self.contents_id = contents_id
        self.type = type

    @property
    def get_key(self) -> 'Key':
        return self.key

    @property
    def get_contents_id(self) -> str:
        return self.contents_id

    @property
    def get_type(self) -> int:
        return self.type

def of(key: 'Key', contents_id: str, type: int):
    return KeyWithType(key, contents_id, type)
```

Please note that Python does not have a direct equivalent to Java's `@Value.Immutable` annotation or the concept of immutable objects in general. The above code uses Python's built-in immutability features like using properties (`get_key`, `get_contents_id`, and `get_type`) instead of public fields, which can be considered as an approximation of immutability.

Also note that there is no direct equivalent to Java's static methods or constructors in Python. Instead, we use a regular function named `of` here.