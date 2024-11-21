Here is the equivalent Python code:

```Python
class Endian:
    BIG = ("big", "BE")
    LITTLE = ("little", "LE")

    def __init__(self, name, short_name):
        self.name = name
        self.short_name = short_name

    @classmethod
    def to_endian(cls, endianess):
        if endianess is not None:
            if (cls.BIG[1].lower() == endianess.lower() or cls.BIG[0].lower() == endianess.lower()):
                return cls.BIG
            elif (cls.LITTLE[1].lower() == endianess.lower() or cls.LITTLE[0].lower() == endianess.lower()):
                return cls.LITTLE
        return None

    def __str__(self):
        return self.name

    def to_short_string(self):
        return self.short_name

    def is_big_endian(self):
        return self.__class__ == Endian.BIG

    def get_display_name(self):
        import re
        return re.sub('([A-Z])', lambda x: ' ' + x.group(0).lower(), self.name)
```

Note that Python does not have an exact equivalent to Java's enum. Instead, we use a class with static members and methods.