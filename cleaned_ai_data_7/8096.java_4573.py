class AbstractRegisterRelativeAddressMsSymbol:
    def __init__(self):
        self.offset = None
        self.type_record_number = None
        self.register_index = None
        self.register_name = None
        self.name = None

    @property
    def offset(self):
        return self._offset

    @offset.setter
    def offset(self, value):
        self._offset = value

    @property
    def type_record_number(self):
        return self._type_record_number

    @type_record_number.setter
    def type_record_number(self, value):
        self._type_record_number = value

    @property
    def register_index(self):
        return self._register_index

    @register_index.setter
    def register_index(self, value):
        self._register_index = value

    @property
    def register_name(self):
        return self._register_name

    @register_name.setter
    def register_name(self, value):
        self._register_name = value

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    def __init_pdb_reader__(self, pdb, reader):
        super().__init__(pdb, reader)

    def get_offset(self):
        return self.offset

    def get_type_record_number(self):
        return self.type_record_number

    def get_register_index(self):
        return self.register_index

    def get_register_name_string(self):
        return str(self.register_name)

    def get_name(self):
        return self.name

    def emit(self, builder):
        builder.append(f"{self.get_symbol_type_name()}: {str(self.register_name)}+{hex(self.offset)}, Type: {pdb.get_type_record(self.type_record_number)}, {self.name}")
