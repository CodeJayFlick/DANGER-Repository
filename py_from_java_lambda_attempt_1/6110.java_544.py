Here is the translation of the Java code to Python:
```
class OriginalProgramModifierListener:
    def modify_original(self, program: 'ghidra.program.database.ProgramDB') -> None:
        raise NotImplementedError
```
Note that I've used type hints for the `program` parameter and the return value. In Python 3.x, you can use string literals to specify types (e.g., `'str'`, `'int'`, etc.). The `-> None:` syntax indicates that this method returns no value.

The rest of the code is simply a class definition with one method, which raises a `NotImplementedError` when called. This is equivalent to the Java interface's single abstract method (`modifyOriginal`).