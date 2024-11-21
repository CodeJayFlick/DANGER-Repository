Here is the translation of the Java code to Python:
```
class NoTransactionException(Exception):
    def __init__(self):
        super().__init__("Transaction has not been started")
```
Note that in Python, we don't need a separate `package` declaration or a `public` access modifier. The class name and method names are also different from Java to Python.

In particular:

* In Python, the equivalent of Java's `extends RuntimeException` is simply inheriting from the built-in `Exception` class.
* The constructor (`__init__`) in Python takes no arguments by default (unlike Java), so we don't need to specify any parameters.