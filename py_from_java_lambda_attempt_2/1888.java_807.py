Here is the translation of the given Java code into equivalent Python:

```Python
class SWIGTYPE_p_void:
    def __init__(self):
        self.swigCPtr = 0

    @classmethod
    def getCPtr(cls, obj):
        return (obj is None) and 0 or obj.swigCPtr
```

Please note that this translation assumes the Java code you provided was a part of an interface generated by SWIG for Python.