Here is the translation of the given Java code into equivalent Python:

```Python
class ImpliedMatchProgramCorrelator:
    MANUAL_SCORE = 1.0
    NAME = "Implied Match"

    def __init__(self, source_program: 'Program', destination_program: 'Program'):
        super().__init__(None, source_program, source_program.memory(), 
                         destination_program, destination_program.memory(),
                         {'name': self.NAME})

    @property
    def name(self):
        return self.NAME

class Program:
    pass

class VTMatchSet:
    pass

class VTScore:
    def __init__(self, score: float):
        self.score = score

class ToolOptions:
    def __init__(self, name: str):
        self.name = name
```

Please note that Python does not have direct equivalent of Java's `@Override` annotation. It is used to indicate that a method is overriding a method in the superclass. In Python, this can be achieved by using the same method signature as the one being overridden.

Also, I've added some placeholder classes (`Program`, `VTMatchSet`, `VTScore`) and objects (like `memory()`), since these were not provided in your original Java code.