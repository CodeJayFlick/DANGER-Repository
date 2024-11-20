Here is the translation of the given Java code into equivalent Python:

```Python
class VirtualFunctionTablePointerMsType:
    PDB_ID = 0x1409

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        reader.read(2)  # Documented padding. Throw away 2 bytes.
        self.pointer_type_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 32)

    @property
    def pdb_id(self):
        return self.PDB_ID

class AbstractPdb:
    pass

class PdbByteReader:
    def read(self, size):
        # implement your own reading logic here
        pass

class RecordNumber:
    @classmethod
    def parse(cls, pdb, reader, category, size):
        # implement your own parsing logic here
        return None

# Usage example:

pdb = AbstractPdb()
reader = PdbByteReader()

try:
    vft_pointer_ms_type = VirtualFunctionTablePointerMsType(pdb, reader)
except Exception as e:
    print(f"An error occurred: {e}")
```

Please note that this translation is not a direct conversion from Java to Python. The given code seems to be part of an IDA Pro plugin and uses custom classes like `AbstractPdb`, `PdbByteReader` and `RecordNumber`. These classes are missing in the provided Java code, so I've left them as abstract placeholders (`pass`) for now.

In a real-world scenario, you would need to implement these classes according to your specific requirements.