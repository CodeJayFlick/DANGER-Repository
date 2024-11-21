Here is a translation of the given Java interface into equivalent Python code:

```Python
from dataclasses import dataclass, field
import jsonschema

@dataclass(frozen=True)
class Tag:
    name: str
    hash: str

def validate_name(tag: Tag) -> None:
    if not isinstance(tag.name, str):
        raise ValueError("Tag name must be a string")
    if len(tag.name) > 64 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._" for c in tag.name.lower()):
        raise ValueError("Invalid characters in the tag name")

def build_tag(name: str, hash: str) -> Tag:
    return Tag(name=name, hash=hash)

def of(name: str, hash: str) -> Tag:
    return build_tag(name, hash)
```

Please note that Python does not have direct equivalent to Java's `interface` or `@Value.Immutable`. Instead we use the built-in `dataclass` decorator from the `dataclasses` module which provides a way to define classes with special behavior like automatically generating `__init__`, `__repr__`, and other methods.

Also, Python does not have direct equivalent to Java's `@JsonSerialize` or `@JsonDeserialize`. Instead we use the built-in support for JSON serialization in Python.