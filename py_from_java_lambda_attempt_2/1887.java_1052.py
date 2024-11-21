Here is the equivalent Python code:

```
class SWIGTYPE_p_unsigned_long_long:
    def __init__(self):
        self.swigcpptr = 0

    @staticmethod
    def get_cpptr(obj):
        return obj.swigcpptr if obj else 0
```