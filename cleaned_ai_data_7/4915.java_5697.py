class ObjectiveC2InstanceVariable:
    def __init__(self, state, reader):
        self._state = state
        if state.is_32bit:
            offset = int.from_bytes(reader.read_next_int().to_bytes(4, 'little'), byteorder='little') & 0xFFFFFFFF
        else:
            offset = int.from_bytes(reader.read_next_long().to_bytes(8, 'little'), byteorder='little')

        name_index = ObjectiveC1Utilities.read_next_index(reader, state.is_32bit)
        if name_index > 0 and reader.is_valid_index(name_index):
            name = reader.read_ascii_string(name_index)

        type_index = ObjectiveC1Utilities.read_next_index(reader, state.is_32bit)
        if type_index > 0 and reader.is_valid_index(type_index):
            type = reader.read_ascii_string(type_index)

        alignment = int.from_bytes(reader.read_next_int().to_bytes(4, 'little'), byteorder='little')
        size = int.from_bytes(reader.read_next_int().to_bytes(4, 'little'), byteorder='little')

    @property
    def offset(self):
        return self._offset

    @property
    def name(self):
        return self._name

    @property
    def type(self):
        return self._type

    @property
    def alignment(self):
        return self._alignment

    @property
    def size(self):
        return self._size

    def to_data_type(self):
        struct = {'ivar_t': {}}
        if self._state.is_32bit:
            struct['ivar_t'].update({'offset': (self.offset, 'DWORD'), 
                                     'name': (None, 'STRING'), 
                                     'type': (None, 'STRING')})
        else:
            struct['ivar_t'].update({'offset': (self.offset, 'QWORD'), 
                                     'name': (None, 'STRING'), 
                                     'type': (None, 'STRING')})

        struct['ivar_t'].update({'alignment': (self.alignment, 'DWORD'), 
                                 'size': (self.size, 'DWORD')})
        
        return {'category_path': ObjectiveC2Constants.CATEGORY_PATH}

    def apply_to(self):
        if self.offset == 0:
            return
        if not self.name or len(self.name) == 0:
            return

        address = _state.program.get_address_factory().get_default_address_space().get_address(self.offset)
        ObjectiveC1Utilities.create_symbol(_state.program, namespace, self.name, address)

    def __str__(self):
        return f'ObjectiveC2InstanceVariable(offset={self.offset}, name="{self.name}", type="{self.type}", alignment={self.alignment}, size={self.size})'
