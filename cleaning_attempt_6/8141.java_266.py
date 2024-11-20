class DataHighLevelShaderLanguageSymbolInternals:
    def __init__(self):
        pass

    @staticmethod
    def parse(pdb: 'AbstractPdb', reader) -> 'DataHighLevelShaderLanguageSymbolInternals':
        result = DataHighLevelShaderLanguageSymbolInternals32(pdb)
        result.type_record_number = RecordNumber.parse(pdb, reader, 32)
        result.register_type = HLSLRegisterType.from_value(reader.parse_unsigned_short_val())
        result.data_slot = reader.parse_unsigned_short_val()
        result.data_offset = reader.parse_unsigned_short_val()
        result.texture_slot_start = reader.parse_unsigned_short_val()
        result.sampler_slot_start = reader.parse_unsigned_short_val()
        result.uav_slot_start = reader.parse_unsigned_short_val()
        result.name = reader.parse_string(pdb, 'StringUtf8Nt')
        return result

    @staticmethod
    def parse32(pdb: 'AbstractPdb', reader) -> 'DataHighLevelShaderLanguageSymbolInternals':
        result = DataHighLevelShaderLanguageSymbolInternals32(pdb)
        result.type_record_number = RecordNumber.parse(pdb, reader, 32)
        result.data_slot = reader.parse_unsigned_int_val()
        result.data_offset = reader.parse_unsigned_int_val()
        result.texture_slot_start = reader.parse_unsigned_int_val()
        result.sampler_slot_start = reader.parse_unsigned_int_val()
        result.uav_slot_start = reader.parse_unsigned_int_val()
        result.register_type = HLSLRegisterType.from_value(reader.parse_unsigned_short_val())
        result.name = reader.parse_string(pdb, 'StringUtf8Nt')
        return result

    @staticmethod
    def parse32Ext(pdb: 'AbstractPdb', reader) -> 'DataHighLevelShaderLanguageSymbolInternals':
        result = DataHighLevelShaderLanguageSymbolInternals32Extended(pdb)
        result.type_record_number = RecordNumber.parse(pdb, reader, 32)
        result.register_index = reader.parse_unsigned_int_val()
        result.data_offset = reader.parse_unsigned_int_val()
        result.bind_space = reader.parse_unsigned_int_val()
        result.bind_slot = reader.parse_unsigned_int_val()
        result.register_type = HLSLRegisterType.from_value(reader.parse_unsigned_short_val())
        result.name = reader.parse_string(pdb, 'StringUtf8Nt')
        return result

    def __init__(self, pdb: 'AbstractPdb'):
        super().__init__()

    @property
    def data_offset(self):
        return self._data_offset

    @data_offset.setter
    def data_offset(self, value):
        self._data_offset = value

    @property
    def register_type(self):
        return self._register_type

    @register_type.setter
    def register_type(self, value):
        self._register_type = value

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value


class DataHighLevelShaderLanguageSymbolInternals32(DataHighLevelShaderLanguageSymbolInternals):
    def __init__(self, pdb: 'AbstractPdb'):
        super().__init__()

    @property
    def data_slot(self):
        return self._data_slot

    @data_slot.setter
    def data_slot(self, value):
        self._data_slot = value

    @property
    def texture_slot_start(self):
        return self._texture_slot_start

    @texture_slot_start.setter
    def texture_slot_start(self, value):
        self._texture_slot_start = value

    @property
    def sampler_slot_start(self):
        return self._sampler_slot_start

    @sampler_slot_start.setter
    def sampler_slot_start(self, value):
        self._sampler_slot_start = value

    @property
    def uav_slot_start(self):
        return self._uav_slot_start

    @uav_slot_start.setter
    def uav_slot_start(self, value):
        self._uav_slot_start = value


class DataHighLevelShaderLanguageSymbolInternals32Extended(DataHighLevelShaderLanguageSymbolInternals):
    def __init__(self, pdb: 'AbstractPdb'):
        super().__init__()

    @property
    def register_index(self):
        return self._register_index

    @register_index.setter
    def register_index(self, value):
        self._register_index = value

    @property
    def bind_space(self):
        return self._bind_space

    @bind_space.setter
    def bind_space(self, value):
        self._bind_space = value

    @property
    def bind_slot(self):
        return self._bind_slot

    @bind_slot.setter
    def bind_slot(self, value):
        self._bind_slot = value


class RecordNumber:
    @staticmethod
    def parse(pdb: 'AbstractPdb', reader) -> int:
        pass  # implement this method


class HLSLRegisterType:
    @staticmethod
    def from_value(value: int) -> str:
        pass  # implement this method

    def __str__(self):
        return self._value


# You need to define the AbstractPdb class and its methods.
