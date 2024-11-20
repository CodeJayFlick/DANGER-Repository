Here is the equivalent Python code:

```Python
class MultipleProgramsStrategy:
    ALL_PROGRAMS = lambda programs, consumer: programs
    
    ONE_PROGRAM_OR_EXCEPTION = lambda programs, consumer: (
        list(program.release(consumer) for program in programs)
        if len(programs) > 1 else None
    )
    
    ONE_PROGRAM_OR_NULL = lambda programs, consumer: (
        None if len(programs) > 1 else programs
    )

def handle_programs(self, programs, consumer):
    pass

# Usage:
strategy = MultipleProgramsStrategy()
programs = [program1, program2]  # list of Program objects
consumer = "some object"  # Object type variable
result = strategy.handle_programs(programs, consumer)
```

Note that Python does not have direct equivalent to Java's interfaces. Instead, we define a class with methods and use lambda functions for the static final strategies.