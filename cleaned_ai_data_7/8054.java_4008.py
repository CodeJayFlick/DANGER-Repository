class AbstractGlobalDataHLSLMsSymbol:
    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader', internals):
        super().__init__(pdb, reader, internals)

# Note that this class is abstract in Java and doesn't have any concrete implementation.
