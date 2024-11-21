Here is the equivalent Python code:

```Python
class Cobol1MsType:
    PDB_ID = 0x000c

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.data = reader.read_remaining_bytes()

    @property
    def pdb_id(self):
        return self.PDB_ID

    def emit(self, builder, bind):
        builder.append("Cobol1MsType\n")
        builder.append(f"  additional data length: {len(self.data)}\n")

# Example usage:
class AbstractPdb:
    pass

class PdbByteReader:
    def read_remaining_bytes(self):
        # This is a placeholder for the actual implementation
        return b''

def main():
    pdb = AbstractPdb()
    reader = PdbByteReader()

    cobol1_ms_type = Cobol1MsType(pdb, reader)
    builder = StringBuilder()
    bind = None  # Not used in this example

    cobol1_ms_type.emit(builder, bind)

if __name__ == "__main__":
    main()
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements or the `@Override` annotation. The equivalent code is written as a single file with no imports and without any annotations.

Also note that this translation assumes that you are familiar with both Java and Python, so I did not provide detailed explanations of each line of code.