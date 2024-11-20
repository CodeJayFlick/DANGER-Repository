class AbstractUserDefinedTypeMsSymbol:
    def __init__(self, pdb, reader, internals):
        super().__init__(pdb, reader)
        self.internals = internals

    @property
    def name(self):
        return self.internals.name()

    @property
    def type_record_number(self):
        return self.internals.type_record_number

    def emit(self, builder):
        builder.append(self.symbol_type_name())
        self.internals.emit(builder)
