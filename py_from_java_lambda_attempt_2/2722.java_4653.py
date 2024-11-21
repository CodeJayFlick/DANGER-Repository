Here is the translation of the Java code to Python:
```
import typing as t

class AutoOptionConsumed(t.Protocol):
    def category(self) -> t.List[str]:
        ...

    def name(self) -> str:  # Note: single value in Python
        ...
```