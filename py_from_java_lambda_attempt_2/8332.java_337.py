Here is the translation of the given Java code into equivalent Python:

```Python
class AbstractBitfieldMsType:
    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)

    @property
    def element_record_number(self):
        return self._element_record_number

    @element_record_number.setter
    def element_record_number(self, value):
        self._element_record_number = value

    @property
    def length(self):
        return self._length

    @length.setter
    def length(self, value):
        self._length = value

    @property
    def position(self):
        return self._position

    @position.setter
    def position(self, value):
        self._position = value

    def emit(self, builder, bind):
        pdb.type_record(self.element_record_number).emit(builder, Bind.NONE)
        builder.append("  : ")
        builder.append(str(self.length))
        builder.append(" <@")
        builder.append(str(self.position))
        builder.append(">")

class RecordNumber:
    pass

class PdbByteReader:
    pass

class AbstractPdb:
    def getTypeRecord(self, record_number):
        return None
```

Please note that this is a direct translation of the Java code into Python. It may not be perfect as it does not include any error handling or additional functionality that might have been present in the original Java code.