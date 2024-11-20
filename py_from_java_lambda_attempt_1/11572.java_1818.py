Here is the translation of the Java enum code to Python:

```
class EmulateExecutionState:
    STOPPED = "STOPPED"
    BREAKPOINT = "BREAKPOINT"
    INSTRUCTION_DECODE = "INSTRUCTION_DECODE"
    EXECUTE = "EXECUTE"
    FAULT = "FAULT"

# You can use this class like a dictionary
print(EmulateExecutionState.STOPPED)  # prints: STOPPED
```

Note that in Python, we don't have an exact equivalent to Java's enum type. Instead, we define a class with string constants as attributes.