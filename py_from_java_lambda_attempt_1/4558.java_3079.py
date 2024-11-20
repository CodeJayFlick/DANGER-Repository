Here is the translation of the Java code to Python:
```
class ProgramLocationPair:
    def __init__(self, program: 'Program', location: 'ProgramLocation'):
        if not isinstance(program, Program):
            raise TypeError("Program cannot be null")
        if not isinstance(location, ProgramLocation):
            raise TypeError("ProgramLocation cannot be null")

        self.program = program
        self.location = location

    @property
    def program(self) -> 'Program':
        return self._program

    @property
    def location(self) -> 'ProgramLocation':
        return self._location


class Program:
    pass


class ProgramLocation:
    pass
```
Note that I've used type hints to indicate the expected types of the `program` and `location` parameters in the constructor, as well as the return types of the `get_program()` and `get_location()` methods. This is not strictly necessary for Python code, but it can be helpful for documentation purposes.

I've also defined two additional classes, `Program` and `ProgramLocation`, to represent the equivalent Java classes. In a real-world implementation, these would likely have their own attributes and behaviors, but in this translation I've kept them simple as placeholders.