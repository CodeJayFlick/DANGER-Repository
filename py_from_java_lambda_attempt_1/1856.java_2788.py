Here is the equivalent Python code:

```Python
class SearchDepth:
    eSearchDepthInvalid = "eSearchDepthInvalid"
    eSearchDepthTarget = "eSearchDepthTarget"
    eSearchDepthModule = "eSearchDepthModule"
    eSearchDepthCompUnit = "eSearchDepthCompUnit"
    eSearchDepthFunction = "eSearchDepthFunction"
    eSearchDepthBlock = "eSearchDepthBlock"
    eSearchDepthAddress = "eSearchDepthAddress"
    kLastSearchDepthKind = "kLastSearchDepthKind"

    def __init__(self, swig_name):
        self.swig_name = swig_name
        SearchDepth.swig_next += 1

    @classmethod
    def swig_to_enum(cls, swig_value):
        if 0 <= swig_value < len(SearchDepth.swig_values) and SearchDepth.swig_values[swig_value].swig_name == str(swig_value):
            return SearchDepth.swig_values[swig_value]
        for i in range(len(SearchDepth.swig_values)):
            if SearchDepth.swig_values[i].swig_name == str(i):
                return SearchDepth.swig_values[i]
        raise ValueError(f"No enum {cls.__name__} with value {swig_value}")

    @classmethod
    def swig_to_string(cls, swig_value):
        for i in range(len(SearchDepth.swig_values)):
            if SearchDepth.swig_values[i].swig_name == str(i):
                return SearchDepth.swig_values[i].swig_name

SearchDepth.swig_next = 0
SearchDepth.swig_values = [obj() for obj in globals().values() if hasattr(obj, 'eSearchDepthInvalid')]
```

Please note that Python does not have direct equivalent of Java's enum. It is more like a class with static values and methods to convert between the two.