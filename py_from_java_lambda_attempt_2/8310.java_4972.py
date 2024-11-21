Here is the translation of the Java code into Python:

```Python
class UnknownX1168MsSymbol:
    PDB_ID = 0x1168

    def __init__(self, pdb, reader):
        self.count = reader.read_int()
        self.type_record_numbers = []
        
        for i in range(self.count):
            type_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 32)
            self.type_record_numbers.append(type_record_number)

class PdbByteReader:
    def read_int(self):
        # Implement your logic to read an integer from the byte stream
        pass

class AbstractPdb:
    def get_type_record(self, record_number):
        # Implement your logic to retrieve a type record by its number
        pass

class RecordNumber:
    @classmethod
    def parse(cls, pdb, reader, category, size):
        # Implement your logic to parse a record number from the byte stream and PDB data
        pass

def emit(symbol, builder):
    builder.append(f"{symbol.get_symbol_type_name()}: Type List: {{")
    
    for type_record_number in symbol.type_record_numbers:
        builder.append(f", {pdb.get_type_record(type_record_number)}")

    builder.append("}\n")

class DelimiterState:
    def __init__(self, prefix, delimiter):
        self.prefix = prefix
        self.delimiter = delimiter

    def out(self, first, string):
        if not first:
            return f"{self.prefix}{self.delimiter} {string}"
        else:
            return string

# Example usage:

pdb = AbstractPdb()
reader = PdbByteReader()

symbol = UnknownX1168MsSymbol(pdb, reader)
builder = StringBuilder()

emit(symbol, builder)

print(builder.toString())
```

Please note that the above Python code is a direct translation of your Java code. However, it does not include any actual implementation for methods like `PdbByteReader.read_int()`, `AbstractPdb.get_type_record(record_number)`, and `RecordNumber.parse(pdb, reader, category, size)` as these would require knowledge about the specific format you are working with (e.g., PDB file).