Here is the translation of the Java code to Python:
```
class AbstractSymbolInternals:
    def __init__(self, pdb):
        if pdb is None:
            raise ValueError("pdb cannot be null")
        self.pdb = pdb
```
Note that I did not include any documentation comments (e.g. `"""`) as they are specific to Java and Python has its own way of documenting code using docstrings.

Also, the following changes were made:

* The class is now defined in Python syntax (`class AbstractSymbolInternals:`) instead of being declared with a `public abstract` keyword.
* The constructor method is renamed from `AbstractSymbolInternals` to `__init__`, which is the standard name for constructors in Python.
* The `Objects.requireNonNull()` check is replaced with a simple `if` statement that raises a `ValueError` if `pdb` is None.