Here is the translation of the Java code to Python:
```
class DemangledLambda:
    def __init__(self, mangled: str, original_demangled: str, name: str):
        super().__init__(mangled, original_demangled, name)

    def get_namespace_name(self) -> str:
        return self.name

    def __str__(self) -> str:
        return self.name

    def add_parameters(self, buffer: str, format: bool = False) -> None:
        pass
```
Note that I've used Python's type hints to indicate the types of the method parameters and return values. This is not strictly necessary for a simple translation like this, but it can help with code readability and maintainability.

Also, in Python, we don't need an `@Override` annotation because methods are dynamically dispatched based on their signature (i.e., the function name and parameter list).