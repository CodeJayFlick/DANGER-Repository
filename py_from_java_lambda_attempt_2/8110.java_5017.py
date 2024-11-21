Here is the translation of the given Java code into Python:

```Python
class AnnotationMsSymbol:
    PDB_ID = 0x1019

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.offset = reader.parse_unsigned_int_val()
        self.segment = pdb.parse_segment(reader)
        count = reader.parse_unsigned_short_val()
        for i in range(count):
            string = reader.parse_string(pdb, 'utf-8')
            self.annotation_string_list.append(string)
        if len(self.annotation_string_list) != count:
            raise PdbException("We are not expecting this--needs investigation")
        reader.align4()

    def get_pdb_id(self):
        return self.PDB_ID

    def emit(self, builder):
        builder.append(f"{self.get_symbol_type_name()}: [{hex(self.segment):04X}:{hex(self.offset):08X}]\n")
        count = 0
        for string in self.annotation_string_list:
            builder.append(f"{count:5d}: {string}\n")
            count += 1

    def get_symbol_type_name(self):
        return "ANNOTATION"


class PdbException(Exception):
    pass


# Example usage:

pdb = None  # Replace with your pdb object
reader = None  # Replace with your reader object

symbol = AnnotationMsSymbol(pdb, reader)
print(symbol.emit("StringBuilder"))  # Replace with your StringBuilder object
```

Please note that Python does not have direct equivalent of Java's `AbstractPdb`, `PdbByteReader` and other classes. You would need to create these objects or use existing ones in your project.

Also, the code is translated as it is written in Java, without any modifications or optimizations for Python.