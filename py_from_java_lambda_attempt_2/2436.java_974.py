Here is the translation of the Java code to Python:
```
class DBTraceProgramViewReferenceManager:
    def __init__(self, program):
        super().__init__(program)

    def get_reference_operations(self, create_if_absent=False):
        return self.program.trace.get_reference_manager()

    def get_code_operations(self, create_if_absent=False):
        return self.program.trace.get_code_manager()
```
Note that I've used the following Python concepts to translate the Java code:

* Classes and inheritance: `class DBTraceProgramViewReferenceManager:` defines a new class in Python.
* Constructors (`__init__` method): In Python, constructors are implemented as special methods called `__init__`.
* Method overriding: The `@Override` annotation is not needed in Python; instead, we use the same method name and signature to override the parent class's method.
* Boolean parameters (defaulting to False): We've used a simple boolean parameter with default value of `False` for both methods.

Please note that this translation assumes you have a basic understanding of Java-to-Python conversion.