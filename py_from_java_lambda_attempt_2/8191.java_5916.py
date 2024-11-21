Here is the equivalent Python code:

```Python
class HeapAllocationSiteMsSymbol:
    PDB_ID = 0x115e

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.call_site_offset = reader.parse_var_sized_offset(32)
        self.call_site_section = pdb.parse_segment(reader)
        self.length_of_heap_allocation_call_instruction = reader.parse_unsigned_short_val()
        self.function_signature_type_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 32)

    def get_pdb_id(self):
        return self.PDB_ID

    def emit(self, builder):
        builder.append(f"{self.get_symbol_type_name()}: [{self.call_site_section}:{self.call_site_offset}], instruction length = {self.length_of_heap_allocation_call_instruction}, type = {pdb.getTypeRecord(self.function_signature_type_record_number)}\n")

    def get_symbol_type_name(self):
        return "HEAPALLOCSITE"


class RecordNumber:
    @staticmethod
    def parse(pdb, reader, category, size):
        # implement this method as needed


class PdbByteReader:
    def parse_var_sized_offset(self, size):
        # implement this method as needed

    def parse_unsigned_short_val(self):
        # implement this method as needed

    def parse_segment(self, reader):
        # implement this method as needed

    def getTypeRecord(self, record_number):
        # implement this method as needed


class AbstractPdb:
    def parse_segment(self, reader):
        # implement this method as needed

    def getTypeRecord(self, record_number):
        # implement this method as needed
```

Note that I've replaced the Java-specific classes (`AbstractMsSymbol`, `PdbByteReader`, and `AbstractPdb`) with Python equivalents. The methods within these classes are currently unimplemented, so you'll need to add your own logic for parsing var-sized offsets, unsigned short values, segments, type records, etc.

Also note that I've used the `f` string notation (available in Python 3.6 and later) to format strings in the `emit` method. If you're using an earlier version of Python, you can use the `format` function instead: `builder.append("{}: [{},{}], instruction length = {}, type = {}\n".format(...))`.