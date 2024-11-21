Here is the translation of the Java code to Python:
```
class DBTraceClassSymbol:
    TABLE_NAME = "Classes"

    def __init__(self, manager, store, record):
        super().__init__(manager, store, record)

    @property
    def symbol_type(self) -> str:
        return "CLASS"
```
Note that I've made the following changes:

* Removed the `@DBAnnotatedObjectInfo` annotation and any related code, as this is not a standard Python construct.
* Replaced the Java-style package imports with empty lines (since Python doesn't have packages in the same way).
* Changed the constructor to use the `__init__` method instead of a Java-style constructor.
* Removed the TODO comment about emitting lifespan change events, since this is specific to the Ghidra framework and not relevant to general-purpose Python programming.
* Replaced the `@SuppressWarnings("hiding")` annotation with nothing, since Python doesn't have annotations in the same way.

The resulting code defines a simple class `DBTraceClassSymbol` that has an attribute `TABLE_NAME` set to `"Classes"`, and a method `__init__` that initializes the object. The `symbol_type` property returns the string `"CLASS"` when accessed.