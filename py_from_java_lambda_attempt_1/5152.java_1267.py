Here is the equivalent Python code:

```
class MSProductType:
    CXX_COMPILER = ("C++ Compiler",)
    C_COMPILER = ("C Compiler",)
    ASSEMBLER = ("Assembler",)
    IMPORT_LINKER = ("Linker",)
    EXPORT_LINKER = ("Linker",)
    IMPORT_EXPORT_LINKER = ("Linker",)
    LINKER = ("Linker",)
    CVT_RES = ("CVTRes",)

    UNKNOWN = ("Unknown",)

    def __init__(self, desc):
        self.desc = desc

    def __str__(self):
        return self.desc
```

Note that Python does not have an equivalent to Java's `enum` type. Instead, we define a class with static variables and methods. The `__init__` method is used to initialize the object, and the `__str__` method returns the string representation of the object.