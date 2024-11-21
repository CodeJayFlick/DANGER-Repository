class AbstractPublic16Or3216MsSymbol:
    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader', internals):
        super().__init__(pdb, reader, internals)

    @property
    def offset(self) -> int:
        return (internals).get_offset()

    @property
    def segment(self) -> int:
        return (internals).get_segment()

    @property
    def name(self) -> str:
        return (internals).get_name()

    def emit(self, builder: 'StringBuilder') -> None:
        builder.append(self.get_symbol_type_name())
        self.internals.emit(builder)
