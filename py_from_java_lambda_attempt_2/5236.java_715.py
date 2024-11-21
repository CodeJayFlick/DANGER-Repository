Here is the translation of the given Java interface into a Python class:

```Python
class StructConverter:
    BYTE = "BYTE"
    WORD = "WORD"
    DWORD = "DWORD"
    QWORD = "QWORD"
    ASCII = "ASCII"
    STRING = "STRING"
    UTF8 = "UTF8"
    UTF16 = "UTF16"
    POINTER = "POINTER"
    VOID = "VOID"

    IBO32 = {"name": "IBO32", "size": 4}
    IBO64 = {"name": "IBO64", "size": 8}

    def to_data_type(self):
        # This method should be implemented based on the actual class members
        pass

# Example usage:
converter = StructConverter()
print(converter.BYTE)  # Output: BYTE
```

Note that Python does not have a direct equivalent of Java's `interface` keyword. Instead, we can use abstract base classes (ABCs) or interfaces implemented by other classes to achieve similar functionality.

In this translation, I've kept the same variable names and structure as in the original code for ease of comparison. However, please note that Python does not have a direct equivalent of Java's `final static` keyword, so we can't replicate it exactly.