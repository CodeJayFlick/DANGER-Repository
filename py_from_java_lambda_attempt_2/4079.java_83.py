Here is the translation of the Java code to Python:
```
class VariableXRefLocationDescriptor:
    def __init__(self, program_location: 'ProgramLocation', program: 'Program'):
        super().__init__(program_location, program)

    def validate(self):
        if self.program_location is None:
            raise ValueError("Cannot create a LocationDescriptor from a null ProgramLocation")
        
        if not isinstance(self.program_location, VariableXRefFieldLocation):
            raise AssertionError(f"Unexpected ProgramLocation type - Cannot create a LocationDescriptor for type: {self.program_location}")

    def get_xref_address(self) -> 'Address':
        return (self.program_location).get_ref_address()
```
Note that I used the `super().__init__` syntax to call the parent class's constructor, and also used Python's built-in exception types (`ValueError`, `AssertionError`) instead of Java's custom exceptions. Additionally, I removed the `@Override` annotations since they are not necessary in Python.

Also, note that I assumed the existence of a `ProgramLocation` and `VariableXRefFieldLocation` classes in your codebase, which would need to be defined separately for this translation to work correctly.