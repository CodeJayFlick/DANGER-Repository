Here is the translation of the Java code into Python:

```Python
class DemangledFunctionIndirect:
    def __init__(self, mangled: str, original_demangled: str):
        super().__init__(mangled, original_demangled)

    def get_type_string(self) -> str:
        return ""

    def add_function_pointer_parens(self, buffer: str, s: str) -> None:
        buffer += s
```

Note that Python does not have direct equivalents for Java's `package`, `public class`, and other keywords. In Python, you can simply define a new class without any additional declarations.

Also note that the `@Override` annotation is used in Java to indicate that a method overrides one from its superclass or interface. This concept doesn't exist in Python, so we don't need it here.