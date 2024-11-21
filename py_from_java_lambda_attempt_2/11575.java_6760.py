Here is the translation of the Java code to Python:
```
class InstructionDecodeException(Exception):
    def __init__(self, reason: str, program_counter: int) -> None:
        super().__init__(f"Instruction decode failed ({reason}), PC={program_counter}")
        self.program_counter = program_counter
```
Note that I've used the built-in `Exception` class in Python as a base class for our custom exception. The constructor (`__init__`) takes two arguments: `reason` and `program_counter`. We use f-strings to create the error message, which is similar to how we did it in Java.

Also note that I've removed the imports from the original code, since Python doesn't require explicit imports for built-in types like strings and integers.