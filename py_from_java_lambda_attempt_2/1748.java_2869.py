Here is the equivalent Python code:

```Python
class DescriptionLevel:
    eDescriptionLevelBrief = "eDescriptionLevelBrief"
    eDescriptionLevelFull = "eDescriptionLevelFull"
    eDescriptionLevelVerbose = "eDescriptionLevelVerbose"
    eDescriptionLevelInitial = "eDescriptionLevelInitial"
    kNumDescriptionLevels = None

    def __init__(self, swig_name):
        self.swig_name = swig_name
        DescriptionLevel.next_value()

    @classmethod
    def next_value(cls):
        cls.next_value += 1

    @staticmethod
    def swig_to_enum(swig_value):
        if 0 <= swig_value < len(DescriptionLevel.values) and DescriptionLevel.values[swig_value].value == swig_value:
            return DescriptionLevel.values[swig_value]
        for i in range(len(DescriptionLevel.values)):
            if DescriptionLevel.values[i].value == swig_value:
                return DescriptionLevel.values[i]
        raise ValueError(f"No enum {cls.__name__} with value {swig_value}")

    @property
    def value(self):
        return self._value

    @property
    def name(self):
        return self._name

    @classmethod
    def values(cls):
        if not hasattr(cls, 'values'):
            cls.values = [cls(eDescriptionLevelBrief), cls(eDescriptionLevelFull),
                           cls(eDescriptionLevelVerbose), cls(eDescriptionLevelInitial)]
        return cls.values


# usage:
print(DescriptionLevel.swig_to_enum(0))  # prints: eDescriptionLevelBrief
```

Note that Python does not have a direct equivalent to Java's `enum` type. Instead, we use classes with static values and methods to achieve similar functionality.