Here is the translation of the given Java code into equivalent Python:

```Python
class SWIGTYPE_p_std__shared_ptrT_llldb_private_ThreadPlan_t:
    def __init__(self):
        self.swigCPtr = 0

    @staticmethod
    def getCPtr(obj):
        if obj is None:
            return 0
        else:
            return obj.swigCPtr
```

Please note that Python does not have direct equivalent of Java's `transient` keyword. Also, the concept of `swigCPtr` and its usage in this code seems to be specific to SWIG (Simplified Wrapper and Interface Generator) which is a software tool for integrating C/C++ libraries with languages like Python.