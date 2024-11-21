Here is the translation of the given Java code into equivalent Python:

```Python
import typing as t

class ToolEventName(t.Protocol):
    def __call__(self) -> str: ...

def tool_event_name(value: str) -> ToolEventName:
    return value
```

Please note that this translation does not exactly replicate the original Java annotation. In particular, in Python, we cannot define an annotation like `@interface` or use a protocol as you would do with Java's interface. Instead, I've defined a simple class `ToolEventName` which is essentially equivalent to the given Java code.

In addition, since there are no specific requirements for this translation (like maintaining compatibility), it might not be exactly what you're looking for if your goal was to translate this annotation into Python.