Here is the translation of the given Java code into equivalent Python:

```Python
class SWIGTYPE_p_int:
    def __init__(self):
        self.swigCPtr = 0

    @staticmethod
    def getCPtr(obj):
        if obj is None:
            return 0
        else:
            return obj.swigCPtr
```

Note that Python does not have direct equivalent of Java's `transient` keyword, which means the variable will be ignored by serialization mechanisms. Also, there are no annotations like `@SuppressWarnings("unused")`, they serve a purpose in Java but do not exist in Python.