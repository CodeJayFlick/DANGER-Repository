Here is the translation of the given Java code into Python:

```Python
class ProgramLocationPluginEvent:
    NAME = "ProgramLocationChange"

    def __init__(self, src: str, loc: 'ProgramLocation', program: 'Program'):
        super().__init__(src, self.NAME)
        
        if not isinstance(loc, object):
            raise TypeError("loc must be an instance of ProgramLocation")
            
        if not isinstance(program, object):
            raise TypeError("program must be an instance of Program")

        self.loc = loc
        self.program_ref = weakref.ref(program)

    def get_location(self) -> 'ProgramLocation':
        return self.loc

    def get_program(self) -> 'Program':
        return self.program_ref()

    def __str__(self):
        if self.loc:
            return f"{type(self.loc).__name__} addr==> {self.loc.get_address()}\n"
        else:
            return super().__str__()
```

Note that Python does not have direct equivalent of Java's `WeakReference` class. Instead, we use the built-in `weakref.ref()` function to create a weak reference to an object.

Also note that in Python, you don't need to declare types for variables or method parameters like you do in Java. However, I've included type hints for clarity and to help with static analysis tools.