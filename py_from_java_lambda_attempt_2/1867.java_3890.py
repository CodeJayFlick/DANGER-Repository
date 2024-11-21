Here is the translation of the given Java code into equivalent Python:

```Python
class SWIGTYPE_p_f_p_q_const_char_p_void__void:
    def __init__(self):
        self.swigCPtr = 0

    @staticmethod
    def getCPtr(obj):
        if obj is None:
            return 0
        else:
            return obj.swigCPtr
```

Please note that Python does not have direct equivalent of Java's `transient` keyword. Also, the concept of a "long" type in Java (which is essentially an integer) has been replaced with Python's built-in integers (`int`).