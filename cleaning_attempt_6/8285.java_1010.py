class RegisterMsSymbol:
    PDB_ID = 0x1106

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 32, "StringUtf8Nt")

    def get_pdb_id(self) -> int:
        return self.PDB_ID


class RegisterName:
    def __init__(self, pdb: 'AbstractPdb', value: int):
        self.pdb = pdb
        self.value = value

    @property
    def register_name(self) -> str:
        # assuming you have a method to convert the value into string name
        return self.convert_value_to_string_name(self.value)

    @staticmethod
    def convert_value_to_string_name(value: int):
        pass


class AbstractPdb:
    pass


class PdbByteReader:
    def parse_unsigned_short_val(self) -> int:
        # assuming you have a method to read unsigned short value from the reader
        return self.read_unsigned_short()


def main():
    pdb = AbstractPdb()
    reader = PdbByteReader()

    symbol = RegisterMsSymbol(pdb, reader)

    print(symbol.get_pdb_id())

if __name__ == "__main__":
    main()
