Here is the translation of the given Java code into equivalent Python:

```Python
class GdbCommandErrorEvent:
    def __init__(self, tail):
        super().__init__(tail)

    @classmethod
    def from_mi2(cls, tail):
        return cls(tail)

    @classmethod
    def from_message(cls, message):
        return cls(message.strip())

# Note: Python does not have a direct equivalent of Java's GdbParseError. You may want to create an exception class for this purpose.
```

This translation assumes that the `AbstractGdbCompletedCommandEvent` and `GdbEvent` classes are also translated into their Python equivalents, which would be abstract base classes (`ABC`) and a generic type respectively.

The key differences between Java and Python in this code include:

1. Inheritance: The constructor of the child class does not need to explicitly call its parent's constructor using `super()`. This is because Python automatically calls the parent's constructor if it is not overridden.
2. Class methods: In Python, you can define a method inside a class definition without having to use the `@classmethod` decorator.
3. Exception handling: Java has built-in support for exceptions through its try-catch block syntax. Python also supports exception handling using try-except blocks but does not have an equivalent of Java's checked exceptions (which are declared in the throws clause).