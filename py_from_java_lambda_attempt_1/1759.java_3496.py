Here is the equivalent Python code:

```Python
class GdbSignal:
    eGdbSignalBadAccess = GdbSignal("eGdbSignalBadAccess")
    eGdbSignalBadInstruction = GdbSignal("eGdbSignalBadInstruction")
    eGdbSignalArithmetic = GdbSignal("eGdbSignalArithmetic")
    eGdbSignalEmulation = GdbSignal("eGdbSignalEmulation")
    eGdbSignalSoftware = GdbSignal("eGdbSignalSoftware")
    eGdbSignalBreakpoint = GdbSignal("eGdbSignalBreakpoint")

    def __init__(self, swig_name):
        self.swig_name = swig_name
        GdbSignal._swig_next += 1

    @classmethod
    def _get_swig_values(cls):
        return [cls.eGdbSignalBadAccess,
                cls.eGdbSignalBadInstruction,
                cls.eGdbSignalArithmetic,
                cls.eGdbSignalEmulation,
                cls.eGdbSignalSoftware,
                cls.eGdbSignalBreakpoint]

    @classmethod
    def swig_to_enum(cls, swig_value):
        if 0 <= swig_value < len(cls._swig_values) and \
           cls._swig_values[swig_value].swig_name == str(swig_value):
            return cls._swig_values[swig_value]
        for value in cls._swig_values:
            if value.swig_name == str(swig_value):
                return value
        raise ValueError(f"No enum {cls.__name__} with value {swig_value}")

    def __str__(self):
        return self.swig_name

GdbSignal._swig_next = 0
```

Please note that Python does not have a direct equivalent to Java's `public` and `private` access modifiers. The `_get_swig_values` method is intended as an internal helper function, but it can still be accessed from outside the class if desired.