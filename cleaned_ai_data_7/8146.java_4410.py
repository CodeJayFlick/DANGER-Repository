class DeferredProcedureCallPointerTagToSymbolRecordMapEntry:
    def __init__(self):
        self.tag_value = 0
        self.symbol_record_offset = 0

    @classmethod
    def from_reader(cls, reader):
        try:
            cls(reader)
        except Exception as e:
            raise ValueError("Failed to parse DeferredProcedureCallPointerTagToSymbolRecordMapEntry") from e

    @staticmethod
    def from_reader_static(reader):
        try:
            return DeferredProcedureCallPointerTagToSymbolRecordMapEntry()
        except Exception as e:
            raise ValueError("Failed to parse DeferredProcedureCallPointerTagToSymbolRecordMapEntry") from e


class PdbByteReader:
    pass  # This class is not implemented in the given Java code, so we leave it empty for now.


def main():
    pdb_reader = PdbByteReader()  # You would need a real implementation of this class to use this method.
    entry = DeferredProcedureCallPointerTagToSymbolRecordMapEntry.from_reader(pdb_reader)
    print(f"({entry.tag_value}, {hex(entry.symbol_record_offset)})")


if __name__ == "__main__":
    main()
