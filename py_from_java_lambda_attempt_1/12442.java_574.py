Here is the translation of the Java code to Python:
```
class CompilerSpecDescription:
    def __init__(self):
        pass

    def get_compiler_spec_id(self) -> str:
        raise NotImplementedError("Subclasses must implement this method")

    def get_compiler_spec_name(self) -> str:
        raise NotImplementedError("Subclasses must implement this method")

    def get_source(self) -> str:
        raise NotImplementedError("Subclasses must implement this method")
```
Note that in Python, we don't have a direct equivalent to Java's `public` interface. Instead, we define a class with abstract methods using the `raise NotImplementedError` statement.

Also, I didn't include any specific implementation for these methods as it seems like you're trying to translate an interface from another language and not provide actual functionality.