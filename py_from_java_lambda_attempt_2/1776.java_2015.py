Here is the equivalent Python code:

```Python
class RunMode:
    eOnlyThisThread = "eOnlyThisThread"
    eAllThreads = "eAllThreads"
    eOnlyDuringStepping = "eOnlyDuringStepping"

    def __init__(self, swig_name):
        self.swig_name = swig_name

    @classmethod
    def swig_to_enum(cls, swig_value):
        if 0 <= swig_value < len(RunMode.__dict__.values()):
            return list(cls.__dict__.values())[swig_value]
        for k in cls.__dict__:
            v = RunMode.__dict__[k]
            if isinstance(v, str) and v == swig_value:
                return v
        raise ValueError(f"No enum {cls.__name__} with value {swig_value}")

    def __str__(self):
        return self.swig_name

    @property
    def swig_value(self):
        # Assuming the order of values in RunMode is preserved, we can use this as a proxy for actual value.
        return list(RunMode.__dict__.values()).index(self.swig_name)

RunMode.eOnlyThisThread = RunMode(eOnlyThisThread)
RunMode.eAllThreads = RunMode(eAllThreads)
RunMode.eOnlyDuringStepping = RunMode(eOnlyDuringStepping)

swig_values = [eOnlyThisThread, eAllThreads, eOnlyDuringSteppin]
```

Please note that Python does not have direct equivalent of Java's `public`, `private` and `final`. The access modifiers are handled differently in Python.