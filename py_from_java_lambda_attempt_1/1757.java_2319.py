Here is the equivalent Python code:

```Python
class FrameComparison:
    eFrameCompareInvalid = "eFrameCompareInvalid"
    eFrameCompareUnknown = "eFrameCompareUnknown"
    eFrameCompareEqual = "eFrameCompareEqual"
    eFrameCompareSameParent = "eFrameCompareSameParent"
    eFrameCompareYounger = "eFrameCompareYounger"
    eFrameCompareOlder = "eFrameCompareOlder"

    def __init__(self, swig_name):
        self.swig_name = swig_name
        FrameComparison._swig_next += 1

    @classmethod
    def swig_to_enum(cls, swig_value):
        if 0 <= swig_value < len(FrameComparison._swig_values) and FrameComparison._swig_values[swig_value].swig_value == swig_value:
            return FrameComparison._swig_values[swig_value]
        for i in range(len(FrameComparison._swig_values)):
            if FrameComparison._swig_values[i].swig_value == swig_value:
                return FrameComposition._swig_values[i]
        raise ValueError(f"No enum {cls.__name__} with value {swig_value}")

    @classmethod
    def swig_to_enum_array(cls):
        return [FrameComparison(x) for x in (FrameComparison.eFrameCompareInvalid, 
                                              FrameComparison.eFrameCompareUnknown,
                                              FrameComparison.eFrameCompareEqual,
                                              FrameComparison.eFrameCompareSameParent,
                                              FrameComparison.eFrameCompareYounger,
                                              FrameComparison.eFrameCompareOlder)]

    def __str__(self):
        return self.swig_name

    @property
    def swig_value(self):
        return self._swig_value

    def __repr__(self):
        return f"FrameComparison('{self.swig_name}')"

FrameComparison._swig_values = FrameComparison.swig_to_enum_array()
FrameComparison._swig_next = 0
```

Please note that Python does not have a direct equivalent to Java's `public` and `private` access modifiers. The `_` prefix is commonly used in Python for variables or methods intended to be private, but it is not enforced by the language itself.