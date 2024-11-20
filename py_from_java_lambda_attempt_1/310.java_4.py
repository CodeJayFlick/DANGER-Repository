Here is the translation of the Java code to Python:
```
import typing as t

class DisassemblyInjectInfo(t.Protocol):
    def lang_ids(self) -> t.List[str]:
        ...

    def priority(self) -> int:
        return 100
```
Note that I used type hints and a protocol (a.k.a. abstract class) to define the `DisassemblyInjectInfo` interface in Python. This is equivalent to the Java annotation-based approach, where we defined an interface with methods annotated with `@Target` and `@Retention`. In Python, we don't need annotations for this purpose; instead, we use type hints and a protocol to achieve similar functionality.

The `lang_ids` method returns a list of strings (equivalent to the Java array), while the `priority` method simply returns an integer value.