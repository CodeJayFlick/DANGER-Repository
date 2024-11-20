Here is the equivalent Python code:

```Python
class CallingConvention:
    UNKNOWN = ("INVALID", -1, "INVALID")
    NEAR_C = ("__cdecl", 0x00, "near right to left push, caller pops stack")
    FAR_C = ("__cdecl", 0x01, "far right to left push, caller pops stack")
    NEAR_PASCAL = ("__pascal", 0x02, "near left to right push, callee pops stack")
    FAR_PASCAL = ("__pascal", 0x03, "far left to right push, callee pops stack")
    NEAR_FAST = ("__fastcall", 0x04, "near left to right push with regs, callee pops stack")
    FAR_FAST = ("__fastcall", 0x05, "far left to right push with regs, callee pops stack")
    SKIPPED = ("", 0x06, "skipped (unused) call index")
    NEAR_STD = ("__stdcall", 0x07, "near standard call")
    FAR_STD = ("__stdcall", 0x08, "far standard call")
    NEAR_SYS = ("__syscall", 0x09, "near sys call")
    FAR_SYS = ("__syscall", 0x0a, "far sys call")
    THISCALL = ("__thiscall", 0x0b, "this call (this passed in register)")
    MIPSCALL = ("", 0x0c, "Mips call")
    GENERIC = ("", 0x0d, "Generic call sequence")
    ALPHACALL = ("", 0x0e, "Alpha call")
    PPCCALL = ("", 0x0f, "PPC call")
    SCHCALL = ("", 0x10, "Hitachi SuperH call")
    ARMCALL = ("", 0x11, "ARM call")
    AM33CALL = ("", 0x12, "AM33 call")
    TRICALL = ("", 0x13, "TriCore Call")
    SH5CALL = ("", 0x14, "Hitachi SuperH-5 call")
    M32RCALL = ("", 0x15, "M32R Call")
    CLRCALL = ("", 0x16, "clr call")
    INLINE = ("", 0x17, "Marker for routines always inlined and thus lacking a convention")
    NEAR_VECTOR = ("__vectorcall", 0x18, "near left to right push with regs, callee pops stack")
    RESERVED = ("", 0x19, "first unused call enumeration")

    BY_VALUE = {i: val for i, val in enumerate([UNKNOWN, *list(map(lambda x: getattr(CallingConvention, x), [y[1] for y in vars(CallingConvention).values() if not y[0].startswith('__')]))])}

    def __init__(self, label, value, info):
        self.label = label
        self.value = value
        self.info = info

    def __str__(self):
        return self.label

    @property
    def getValue(self):
        return self.value

    @property
    def getInfo(self):
        return self.info

    @classmethod
    def fromValue(cls, val):
        return cls.BY_VALUE.get(val, UNKNOWN)
```

Please note that Python does not support enum directly like Java. The above code uses a dictionary to simulate the behavior of an enum in Java.