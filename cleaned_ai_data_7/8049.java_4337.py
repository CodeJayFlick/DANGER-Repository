class AbstractDataHighLevelShaderLanguageMsSymbol:
    def __init__(self, pdb, reader, internals):
        super().__init__(pdb, reader)
        self.internals = internals

    @property
    def data_offset(self):
        return self.internals.data_offset

    @property
    def register_type(self):
        return self.internals.register_type

    @property
    def type_record_number(self):
        return self.internals.type_record_number

    @property
    def name(self):
        return self.internals.name

    def emit(self, builder):
        builder.append(self.symbol_type_name)
        self.internals.emit(builder)

class DataHighLevelShaderLanguageSymbolInternals:
    def __init__(self):
        pass  # Initialize your internal variables here if needed

    @property
    def data_offset(self):
        return None  # Replace with actual implementation

    @property
    def register_type(self):
        return None  # Replace with actual implementation

    @property
    def type_record_number(self):
        return None  # Replace with actual implementation

    @property
    def name(self):
        return None  # Replace with actual implementation

    def emit(self, builder):
        pass  # Implement your emission logic here if needed


class AbstractMsSymbol:
    def __init__(self, pdb, reader):
        self.pdb = pdb
        self.reader = reader

    @property
    def symbol_type_name(self):
        return None  # Replace with actual implementation

