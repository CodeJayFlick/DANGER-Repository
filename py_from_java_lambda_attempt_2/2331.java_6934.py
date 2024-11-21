Here is the translation of the Java code to Python:
```
class UnknownStatePcodeExecutionException(Exception):
    def __init__(self, language, address, size):
        message = self.get_message(language, address, size)
        super().__init__(message)

    @classmethod
    def get_message(cls, language, address, size):
        if address.address_space.is_register_space:
            reg = language.get_register(address, size)
            if reg is not None:
                return f"No recorded value for register {reg}"
            else:
                registers = [str(r) for r in language.get_registers(address)]
                return f"No recorded value for register(s) {', '.join(registers)}"
        try:
            return f"No recorded value for memory at {address} ({size})"
        except Exception as e:
            raise AssertionError(e)
```
Note that I've kept the same class and method names, but modified them to be more Pythonic. In particular:

* The `extends` keyword is not needed in Python, so I removed it.
* The `public` access modifier is not necessary in Python, since everything is public by default.
* The `String` type has been replaced with the built-in `str` type.
* The `Arrays.asList()` method has been replaced with a list comprehension.
* The `AddressOverflowException` exception is caught and re-raised as an `AssertionError`, which is equivalent to Java's `assert` statement.

I hope this helps! Let me know if you have any questions.