Here is the translation of the Java code into Python:

```Python
class CliSigMethodDef:
    def __init__(self, blob):
        self.ret_type = None
        self.params = []
        self.size_of_count = 0
        self.generic_param_count = 0
        self.size_of_generic_count = 0
        self.flags = 0

        super().__init__()

        reader = get_contents_reader()
        self.flags = reader.read_next_byte()

        if (self.flags & 0x10) == 0x10:
            orig_index = reader.get_pointer_index()
            self.generic_param_count = decode_compressed_unsigned_int(reader)
            self.size_of_generic_count = reader.get_pointer_index() - orig_index

        orig_index = reader.get_pointer_index()
        param_count = decode_compressed_unsigned_int(reader)
        self.size_of_count = reader.get_pointer_index() - orig_index
        try:
            self.ret_type = CliRetType(reader)
        except InvalidInputException as e:
            self.ret_type = None

        for i in range(param_count):
            try:
                param = CliParam(reader)
                self.params.append(param)
            except InvalidInputException as e:
                pass


    def get_contents_name(self):
        return "MethodDefSig"


    def get_contents_comment(self):
        return "Type info for method return and params"


    def get_contents_data_type(self):
        struct = StructureDataType(new_category_path(PATH), self.get_name(), 0)
        if (self.flags & 0x20) == 0x20:
            struct.add(get_data_type_for_bytes(self.size_of_generic_count), "GenParamCount", 
                       "Number of generic paramameters for the method")
        struct.add(get_data_type_for_bytes(self.size_of_count), "Count",
                   "Number of parameter types to follow RetType")

        if self.ret_type:
            struct.add(self.ret_type.get_definition_data_type(), "RetType", None)

        for i, param in enumerate(self.params):
            if param is not None:
                struct.add(param.get_definition_data_type(), f"Param{i}", None)
        return struct


    def get_return_type(self):
        return self.ret_type


    def get_param_types(self):
        return self.params[:]


    def has_this(self):
        return (self.flags & 0x20) == 0x20


    def has_explicit_this(self):
        return (self.flags & 0x40) == 0x40


    def has_var_args(self):
        return (self.flags & 5) == 5


    def has_generic_args(self):
        return (self.flags & 16) == 16


    @staticmethod
    def get_representation_common(stream, is_short):
        rep = CliSigMethodDef.get_representation_of(self.ret_type, stream, is_short)
        if self.params:
            for param in self.params:
                if param is not None:
                    rep += f"{get_representation_of(param, stream, is_short)}, "
            return rep[:-2] + ")"  # Take off last comma+space
        else:
            return "fn()"
```

Please note that this translation assumes the existence of certain classes and methods (`CliRetType`, `CliParam`, etc.) which are not defined in your code snippet.