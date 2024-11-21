class AbstractLocalProcedureStartMsSymbol:
    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader', internals):
        super().__init__(pdb, reader, internals)

    @property
    def special_type_string(self) -> str:
        return "Type"

