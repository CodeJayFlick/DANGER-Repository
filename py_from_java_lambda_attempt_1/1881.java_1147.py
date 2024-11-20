Here is the translation of the given Java code into equivalent Python:

```Python
class SWIGTYPE_p_std__shared_ptrT_llldb_private_File_t:
    def __init__(self):
        self.swigCPtr = 0

    @staticmethod
    def getCPtr(obj):
        if obj is None:
            return 0
        else:
            return obj.swigCPtr
```

Please note that Python does not have direct equivalent of Java's `transient` keyword. Also, the concept of a "pointer" in C++ or Java doesn't exist directly in Python (it's more like references).