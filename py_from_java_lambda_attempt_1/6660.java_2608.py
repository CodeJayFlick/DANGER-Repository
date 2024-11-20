Here is the translation of the given Java code into equivalent Python:

```Python
class PatternInfoRowObject:
    def __init__(self, type: 'PatternType', bit_sequence: 'DittedBitSequence', c_reg_filter: 'ContextRegisterFilter'):
        self.type = type
        self.bit_sequence = bit_sequence
        self.c_reg_filter = c_reg_filter
        self.alignment = None

    @property
    def pattern_type(self):
        return self.type

    @property
    def ditted_bit_sequence(self):
        return self.bit_sequence

    @property
    def context_register_filter(self):
        return self.c_reg_filter

    @property
    def alignment(self):
        return self.alignment

    @alignment.setter
    def alignment(self, value: int):
        self.alignment = value

    @property
    def note(self):
        return None  # Note is not implemented in the Java code. This line represents that.

    @note.setter
    def note(self, value: str):
        if value:
            self.note = value.strip()

    def __hash__(self):
        hash_value = 17
        hash_value = 31 * hash_value + self.type.__hash__()
        hash_value = 31 * hash_value + self.bit_sequence.__hash__()
        hash_value = 31 * hash_value + hash(self.c_reg_filter)
        if self.alignment is not None:
            hash_value = 31 * hash_value + hash(self.alignment)
        return hash_value

    def __eq__(self, other):
        if self == other:  # Check for the same object
            return True
        elif isinstance(other, PatternInfoRowObject):  # Check for another instance of this class
            if not (other.type.__eq__(self.type) and 
                    other.bit_sequence.__eq__(self.bit_sequence) and 
                    hash(self.c_reg_filter) == hash(other.c_reg_filter)):
                return False
            if self.alignment is None:
                alignment = other.alignment
            else:
                alignment = self.alignment
            return (alignment == other.alignment)
        return NotImplemented

def export_xml_file(rows: list, xml_file: str, postbits: int, totalbits: int):
    try:
        with open(xml_file, 'w') as f_writer:
            b_writer = BufferedWriter(f_writer)
            b_writer.write("<patternlist>\n")
            b_writer.write("   <patternpairs totalbits=\"{}\" postbits=\"{}\">\n".format(totalbits, postbits))
            for row in rows:
                if row.pattern_type == 'PRE':
                    b_writer.write("     <data>{}</data>\n".format(row.ditted_bit_sequence.hex_string()))
                elif row.pattern_type == 'FIRST':
                    b_writer.write("     <data>{}</data>\n".format(row.ditted_bit_sequence.hex_string()))

            alignment = None
            c_reg_filter = None
            for row in rows:
                if row.pattern_type == 'FIRST':
                    alignment = row.alignment
                    c_reg_filter = row.context_register_filter
                    break

            if alignment is not None:
                b_writer.write("     <align mark=\"0\" bits=\"{}\">\n".format(str(Integer.numberOfTrailingZeros(alignment))))
                b_writer.write("</align>\n")
            if c_reg_filter is not None:
                for entry in c_reg_filter.value_map().items():
                    name = entry[0]
                    value = str(entry[1])
                    b_writer.write("     <setcontext name=\"{}\" value=\"{}\">\n".format(name, value))
                    b_writer.write("</setcontext>\n")

            b_writer.write("     <funcstart/>\n")
            b_writer.write("   </patternpairs>\n")
            b_writer.write("</patternlist>\n")

    except IOError as e:
        print(f"Error: {e}")
```

This Python code is equivalent to the given Java code. It defines a class `PatternInfoRowObject` with similar properties and methods, including an overridden `__hash__` method for hash-based operations and an overridden `__eq__` method for equality checks.

The function `export_xml_file` takes in a list of `PatternInfoRowObject`, the destination XML file name, postbits count, and total bits count. It writes this information to the specified XML file using Python's built-in string formatting capabilities.