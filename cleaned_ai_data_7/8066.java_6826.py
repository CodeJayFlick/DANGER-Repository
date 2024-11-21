# This class represents various flavors of Local Managed Procedure symbol.
class AbstractLocalManagedProcedureMsSymbol:
    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader', str_type):
        super().__init__(pdb, reader, str_type)

    # Constructor for this symbol.
    # @param pdb {link AbstractPdb} to which this symbol belongs.
    # @param reader {link PdbByteReader} from which this symbol is deserialized.
    # @param strType {link StringParseType} to use.
    # @throws PdbException upon error parsing a field.
