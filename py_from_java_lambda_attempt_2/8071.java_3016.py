Here is the translation of the given Java code into equivalent Python:

```Python
class AbstractLocalProcedureStartMsSymbol:
    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader', internals):
        super().__init__(pdb, reader, internals)

    @property
    def special_type_string(self) -> str:
        return "Type"

```

Note that Python does not have direct equivalent of Java's abstract classes and interfaces. However, we can achieve similar functionality using inheritance in Python.

Also note that the `@Override` annotation is used to indicate that a method overrides a method from its superclass. In Python, this concept doesn't exist explicitly but it can be achieved by defining methods with same name as those defined in parent class.

In addition, Python's type hinting system allows us to specify types for variables and function parameters using the `->` syntax. This is similar to Java's type annotations, but not exactly equivalent.