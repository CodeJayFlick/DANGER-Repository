Here is the translation of the given Java code into equivalent Python:

```Python
class GdbDebugOutputEvent:
    def __init__(self, tail):
        super().__init__(tail)

# This line imports a custom exception class from another module.
from agent.gdb.manager.parsing import GdbParseError

class AbstractGdbOutputEvent:  # No implementation provided in the Java code
    pass


if __name__ == "__main__":
    try:
        event = GdbDebugOutputEvent("some_tail")
    except GdbParseError as e:
        print(f"An error occurred while parsing the tail: {e}")
```

Please note that Python does not have direct equivalent of Java's package and import statements. The `from agent.gdb.manager.parsing import GdbParseError` line is used to import a custom exception class from another module, which might be defined elsewhere in your project.

Also, I did not implement the abstract base class (`AbstractGdbOutputEvent`) as it was missing any implementation details in the original Java code.