Here is the translation of the given Java code into equivalent Python:

```Python
class EntryThisMsSymbol:
    PDB_ID = 0x000e

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.this_sym = reader.parse_unsigned_byte_val()
        # Don't know what data might remain.
        self.bytes_remaining = reader.get_limit() - reader.get_index()

    def get_pdb_id(self):
        return self.PDB_ID

    def emit(self, builder):
        builder.append(f"{self.symbol_type_name()}, 'this' symbol: {self.this_sym}; byte length of remaining data = {self.bytes_remaining}")

    @property
    def symbol_type_name(self):
        return "ENTRYTHIS"


class PdbByteReader:
    pass


class AbstractPdb:
    pass


class AbstractMsSymbol:
    def __init__(self, pdb, reader):
        self.pdb = pdb
        self.reader = reader

    def get_pdb_id(self):
        raise NotImplementedError("Method not implemented")

    def emit(self, builder):
        raise NotImplementedError("Method not implemented")


def main():
    # Example usage of the EntryThisMsSymbol class.
    pdb = AbstractPdb()
    reader = PdbByteReader()

    entry_this_ms_symbol = EntryThisMsSymbol(pdb, reader)

    print(entry_this_ms_symbol.symbol_type_name())
    print(f"PDB ID: {entry_this_ms_symbol.get_pdb_id()}")
    builder = StringBuilder()
    entry_this_ms_symbol.emit(builder)
    print(builder)


if __name__ == "__main__":
    main()

```

Please note that Python does not have direct equivalent of Java's `package`, `import` statements. Also, the provided code seems to be part of a larger program and may require additional classes or functions for proper execution.