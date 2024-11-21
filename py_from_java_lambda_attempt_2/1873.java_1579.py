Here is the translation of the given Java code into equivalent Python:

```Python
class SWIGTYPE_p_llldb_ConnectionStatus:
    def __init__(self):
        self.swigCPtr = 0

    @staticmethod
    def getCPtr(obj):
        if obj is None:
            return 0
        else:
            return obj.swigCPtr
```

Please note that Python does not have direct equivalent of Java's `transient` keyword. Also, the concept of garbage collection in Python makes it unnecessary to manually manage memory like we do with `swigCPtr`.