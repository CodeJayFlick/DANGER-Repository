Here is the translation of the given Java enum class into a Python equivalent:

```Python
# Enum for MethodType in Android Verifier
class MethodType:
    UNKNOWN = 0
    DIRECT = 1
    STATIC = 2
    VIRTUAL = 3
    SUPER = 4
    INTERFACE = 5
    POLYMORPHIC = 6

print(MethodType.UNKNOWN)  # prints: 0
```

Note that Python does not have a direct equivalent to Java's enum. The above code uses a class with integer constants, which serves the same purpose as an enum in Java.