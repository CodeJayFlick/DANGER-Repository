Here is the translation of the Java code to Python:
```
import typing as t

class AutoOptionDefined(t.Protocol):
    def category(self) -> t.List[str]:
        ...

    def type(self) -> str:  # default OptionType.NO_TYPE
        ...

    def name(self) -> t.Sequence[str]:  # equivalent of String[] in Java
        ...

    def help(self, topic: str = "") -> 'HelpInfo':
        return HelpInfo(topic=topic)

    def description(self) -> str:
        ...
```
Note that I used the `typing` module to define a protocol (similar to an interface in Java), which is a way to define a set of methods that must be implemented by any class that inherits from it. The `Protocol` type is available in Python 3.8 and later.

I also replaced the `@interface` syntax with a simple class definition, since there is no direct equivalent of an interface or annotation processor in Python.

The rest of the code remains similar to the Java version, with some minor adjustments for Python's syntax and typing system.