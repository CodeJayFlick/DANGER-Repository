Here is the equivalent Python code:

```Python
class EntropyKnot:
    NONE = ("None", None)
    X86 = ("x86 code", {"name": "x86", "entropy": 5.94, "confidence": 0.4})
    ARM = ("ARM code", {"name": "arm", "entropy": 5.1252, "confidence": 0.51})
    THUMB = ("THUMB code", {"name": "thumb", "entropy": 6.2953, "confidence": 0.5})
    POWER_PC = ("PowerPC code", {"name": "powerpc", "entropy": 5.6674, "confidence": 0.52})
    ASCII = ("ASCII strings", {"name": "ascii", "entropy": 4.7, "confidence": 0.5})
    COMPRESSED = ("Compressed", {"name": "compressed", "entropy": 8.0, "confidence": 0.5})
    UTF16 = ("Unicode UTF16", {"name": "utf16", "entropy": 3.21, "confidence": 0.2})

    def __init__(self, label, record):
        self.label = label
        self.record = record

    def __str__(self):
        return self.label

    def get_record(self):
        return self.record
```

Note that Python does not have an exact equivalent to Java's enum type. Instead, we use a class with static variables and define the constants as tuples or dictionaries within the class definition.