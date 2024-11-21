Here is the translation of the Java code to Python:
```
class CodeUnitContainer:
    def __init__(self, code_unit):
        self.code_unit = code_unit
        self.mnemonic = code_unit.get_mnemonic_string()
        self.arity = code_unit.get_num_operands()

    def __str__(self):
        return f"{self.code_unit.__str__()} @ {self.code_unit.get_address_string(False, True)}"

    def get_code_unit(self):
        return self.code_unit

    def get_mnemonic(self):
        return self.mnemonic

    def get_arity(self):
        return self.arity
```
Note that I've used the following Python features to translate the Java code:

* Classes and objects are defined using the `class` keyword.
* The constructor (`__init__`) is defined with a similar syntax to Java's constructor.
* Methods (e.g., `toString`, `getCodeUnit`, etc.) are defined as instance methods, using the same name as in Java.
* Python uses f-strings for string formatting, which replaces the need for concatenation and interpolation.
* The `@Override` annotation is not needed in Python, since method overriding works differently.

This code should be equivalent to the original Java code.