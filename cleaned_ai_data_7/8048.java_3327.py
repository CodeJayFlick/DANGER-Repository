class AbstractConstantMsSymbol:
    def __init__(self, pdb, reader, record_number_size, str_type):
        self.type_record_number = None  # equivalent to RecordNumber.parse(pdb, reader, RecordCategory.TYPE, record_number_size)
        self.value = reader.read_unsigned_short()  # equivalent to new Numeric(reader).value
        self.name = reader.read_string(str_type)  # equivalent to reader.parseString(pdb, strType)

    @property
    def type_record_number(self):
        return self.type_record_number

    @property
    def value(self):
        return self.value

    @property
    def name(self):
        return self.name

    def emit(self, builder):
        builder.append(f"{self.get_symbol_type_name()}: Type: {pdb.get_type_record(self.type_record_number).toString()}, Value: {self.value}, {self.name}")
