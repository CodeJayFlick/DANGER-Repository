Here is the translation of the Java code to Python:
```
class AddressTranslator:
    def translate(self, address: 'ghidra.program.model.address.Address', 
                  primary_program: 'ghidra.program.model.Program', 
                  program: 'ghidra.program.model.Program') -> 'ghidra.program.model.address.Address':
        pass  # implementation left out
```
Note that I've used type hints to indicate the expected types of the method parameters and return value, but these are not enforced by Python itself. The `pass` statement is a placeholder for the actual implementation of the `translate` method.

In Python, we don't have an equivalent concept to Java's interfaces or abstract classes, so I've used a regular class with no methods implemented (yet). If you want to define a protocol or interface in Python, you can use ABCs (Abstract Base Classes) from the `abc` module.