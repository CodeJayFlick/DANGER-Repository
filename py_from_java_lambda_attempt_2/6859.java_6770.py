Here is the translation of the Java code to Python:

```Python
class DecompiledFunction:
    def __init__(self, signature: str, c: str):
        self.signature = signature
        self.c = c

    @property
    def get_signature(self) -> str:
        return self.signature

    @property
    def get_c(self) -> str:
        return self.c


# Example usage:

func1 = DecompiledFunction("int foo(double d)", "some C code")
print(func1.get_signature)
print(func1.get_c)

```

Note that Python does not have direct equivalent of Java's `public` and `private` access modifiers. In Python, everything is public by default unless you use the double underscore prefix (`__`) to create a private attribute (which can still be accessed using name mangling).