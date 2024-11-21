class CliSigStandAloneMethod:
    def __init__(self, blob):
        self.sentinel_index = -1
        self.flags = 0x00
        self.size_of_count = 0
        self.ret_type = None
        self.params = []

        reader = BinaryReader(blob)
        flags = reader.read_next_byte()
        orig_index = reader.get_pointer_index()
        param_count = decode_compressed_unsigned_int(reader)
        size_of_count = (reader.get_pointer_index() - orig_index)

        try:
            ret_type = CliRetType(reader)
        except InvalidInputException as e:
            ret_type = None

        for i in range(param_count):
            if reader.peek_next_byte() == CliElementType.ELEMENT_TYPE_SENTINEL.id():
                reader.read_next_byte()
                self.sentinel_index = i
            try:
                param = CliParam(reader)
                self.params.append(param)
            except InvalidInputException as e:
                self.params[i] = None

    def get_contents_name(self):
        return "StandAloneMethodSig"

    def get_contents_comment(self):
        return "Typically for calli instruction; Type info for method return and params"

    def get_contents_data_type(self):
        struct = StructureDataType(PATH, self.get_name(), 0)
        struct.add(BYTE, "flags", "ORed VARARG/DEFAULT/C/STDCALL/THISCALL/FASTCALL and HASTHIS/EXPLICITTHIS")
        struct.add(get_data_type_for_bytes(size_of_count), "Count", "Number of param types to follow RetType")
        if self.ret_type:
            struct.add(self.ret_type.get_definition_data_type(), "RetType", None)
        for param in self.params:
            if param is not None:
                struct.add(param.get_definition_data_type(), None, None)

    def get_return_type(self):
        return self.ret_type

    def get_params(self):
        return self.params[:]

    @property
    def has_this(self):
        return (self.flags & 0x20) == 0x20

    @property
    def has_explicit_this(self):
        return (self.flags & 0x40) == 0x40

    @property
    def has_var_args(self):
        return (self.flags & 5) == 5

    def get_calling_convention(self):
        if self.flags & 1:
            # cdecl
            return CallingConvention.C
        elif self.flags & 2:
            # stdcall
            return CallingConvention.STDCALL
        elif self.flags & 3:
            # ecx/rcx is this pointer
            return CallingConvention.THISCALL
        elif self.flags & 4:
            # ecx/rdx are the first two parameters, standard x64 convention
            return CallingConvention.FASTCALL

    def get_representation_common(self, stream, is_short):
        rep = self.get_representation_of(self.ret_type, stream, is_short) + " fn ("
        for param in self.params:
            if param is None:
                rep += "unidentified_param_type, "
            else:
                rep += self.get_representation_of(param, stream, is_short) + ", "

        if len(self.params) > 0:
            rep = rep[:-2]  # Take off last comma+space
        rep += ")"
        return rep

class CliRetType:
    def __init__(self, reader):
        pass

class CliParam:
    def __init__(self, reader):
        pass

class StructureDataType:
    def add(self, data_type, name, comment):
        pass

def decode_compressed_unsigned_int(reader):
    pass

def get_data_type_for_bytes(size_of_count):
    pass
