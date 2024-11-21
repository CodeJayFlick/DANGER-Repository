Here is the equivalent Python code:

```
class SWIGTYPE_p_p_char:
    def __init__(self):
        self._cptr = 0

    @classmethod
    def get_cptr(cls, obj):
        return 0 if obj is None else obj._cptr
```