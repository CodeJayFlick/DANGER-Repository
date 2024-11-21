Here is the translation of the given Java code into Python:

```Python
class GhidraScriptConstants:
    """A class to hold constants to be shared for clients of this package."""

    USER_SCRIPTS_DIR_PROPERTY = "ghidra.user.scripts.dir"
    DEFAULT_SCRIPT_NAME = "NewScript"

GhidraScriptConstants()
```

Note that in the Python version, we don't need a `public` keyword as it is not necessary. Also, there's no concept of static variables or methods like Java has; instead, you can use class-level attributes and functions to achieve similar functionality.