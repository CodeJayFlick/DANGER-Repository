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

