Here is the translation of the given Java code into equivalent Python:

```Python
class PackingType:
    """specifies the pack setting which applies to a composite data type.
       This can be DISABLED, DEFAULT, EXPLICIT."""
    
    class Disable: pass  # constant for disabled packing
    
    class Default: pass   # constant for default packing
    
    class Explicit: pass  # constant for explicit packing

# usage example:
print(PackingType.Disable)  # prints the disable constant
```

Note that Python does not have an exact equivalent to Java's enum. However, we can achieve similar functionality using classes and constants in Python.