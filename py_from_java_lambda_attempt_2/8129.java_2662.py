Here is the equivalent Python code:

```Python
class ChangeExecutionModel32MsSymbol:
    PDB_ID = 0x020a

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader, 32)
        self.parse_specifics(reader)

    def get_pdb_id(self):
        return self.PDB_ID

    def get_symbol_type_name(self):
        return "CEXMODEL32"

    def parse_specifics(self, reader):
        model = None
        subtype = None
        flag = None
        offset_to_function_table = None
        segment_of_function_table = None
        
        if model == 'COBOL':
            subtype = reader.parse_unsigned_short_val()
            flag = reader.parse_unsigned_short_val()

        elif model in ['PCODE', 'PCODE32MACINTOSH', 'PCODE32MACINTOSH_NATIVE_ENTRY_POINT']:
            offset_to_function_table = reader.parse_unsigned_int_val()
            segment_of_function_table = reader.parse_unsigned_short_val()

        # Add more cases as needed
```

Note that Python does not have direct equivalents for Java's `public`, `private`, and `protected` access modifiers. In this translation, I've omitted these keywords to keep the code concise.

Also, in Python, we don't need to specify a return type for methods or functions. The method will automatically return None if no value is explicitly returned.

The `parse_specifics` method has been modified slightly from its Java counterpart. It now uses Python's conditional statements (`if`, `elif`) instead of the switch statement used in Java, and it initializes variables with default values before assigning them new values based on certain conditions.