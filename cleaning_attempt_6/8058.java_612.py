class AbstractGlobalProcedureStartMipsMsSymbol:
    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader', internals):
        super().__init__(pdb, reader, internals)

    @property
    def special_type_string(self) -> str:
        return "Type"

# This is equivalent to the Java interface or abstract class declaration.
class ProcedureStartMipsSymbolInternals:
    pass

class PdbException(Exception):
    pass

class AbstractPdb:
    pass

class PdbByteReader:
    pass
