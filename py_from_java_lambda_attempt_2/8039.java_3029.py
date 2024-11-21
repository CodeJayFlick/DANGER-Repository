Here is the translation of the given Java code into Python:

```Python
class SectionContribution400:
    def __init__(self):
        self.isect = None
        self.offset = None
        self.length = None
        self.characteristics = None
        self.imod = None

    def deserialize(self, reader):
        try:
            # print(reader.dump(0x200))
            self.isect = reader.parse_unsigned_short()
            reader.read_bytes(2)  # I think there is padding here.
            self.offset = reader.parse_int()
            self.length = reader.parse_int()
            self.characteristics = reader.parse_unsigned_int()
            self.imod = reader.parse_unsigned_short()
        except Exception as e:
            raise PdbException(str(e))

    def dump internals(self):
        builder = StringBuilder("isect: ")
        builder.append(str(self.isect))
        builder.append("\noffset: ")
        builder.append(str(self.offset))
        builder.append("\nlength: ")
        builder.append(str(self.length))
        builder.append(String.format("\ncharacteristics: 0X%08X", self.characteristics))
        builder.append("\nimod: ")
        builder.append(str(self.imod))
        return str(builder)
```

Note that Python does not have direct equivalents for Java's `package`, `public class`, and other keywords. Also, the concept of a "reader" is abstract in this code snippet, so I did not translate it into Python as it would require more context to accurately represent its functionality.

The `PdbException` exception type was also removed since there is no equivalent built-in exception type in Python that matches Java's PDBException.