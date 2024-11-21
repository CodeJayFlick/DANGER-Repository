Here is the translation of the given Java code into equivalent Python:

```Python
class CliNativeType:
    NATIVE_TYPE_END = 0x00
    NATIVE_TYPE_VOID = 0x01
    # ... (all enum values)

    def __init__(self, id):
        self.id = id

    @classmethod
    def from_int(cls, id):
        for value in cls.__dict__.values():
            if isinstance(value, int) and value == id:
                return value
        return None


class CliSafeArrayElemType:
    VT_I2 = 0x2
    # ... (all enum values)

    def __init__(self, id):
        self.id = id

    @classmethod
    def from_int(cls, id):
        for value in cls.__dict__.values():
            if isinstance(value, int) and value == id:
                return value
        return None


class CliBlobMarshalSpec:
    INIT_VALUE = -1
    CLIBLOBMARSHALSPEC_GUID_LENGTH = 0x26

    def __init__(self, blob):
        super().__init__(blob)
        reader = blob.get_contents_reader()
        self.native_intrinsic = CliNativeType.from_int(reader.read_next_byte())

        if self.native_intrinsic in [CliNativeType.NATIVE_TYPE_ARRAY,
                                       CliNativeType.NATIVE_TYPE_FIXEDARRAY]:
            self.array_elem_type = CliNativeType.from_int(reader.read_next_byte())
            orig_index = reader.get_pointer_index()
            self.array_param_num = decode_compressed_unsigned_int(reader)
            self.array_param_num_bytes = (reader.get_pointer_index() - orig_index)
            if blob.contents_size > 2 + self.array_param_num_bytes:
                orig_index = reader.get_pointer_index()
                self.array_num_elem = decode_compressed_unsigned_int(reader)
                self.array_num_elem_bytes = (reader.get_pointer_index() - orig_index)

        elif self.native_intrinsic == CliNativeType.NATIVE_TYPE_FIXEDSYSSTRING:
            self.fixed_string_id = reader.read_next_byte()

        elif self.native_intrinsic == CliNativeType.NATIVE_TYPE_CUSTOMMARSHALER:
            self.custom_marshaller_guid_or_type_name = \
                reader.read_terminated_string(reader.get_pointer_index(), '\0')
            self.custom_marshaller_type_name = \
                reader.read_terminated_string(reader.get_pointer_index(), '\0')
            if reader.peek_next_byte() > 0:
                self.custom_marshaller_cookie = \
                    reader.read_terminated_string(reader.get_pointer_index(), '\0')

        elif self.native_intrinsic == CliNativeType.NATIVE_TYPE_SAFEARRAY:
            self.safe_array_elem_type = CliSafeArrayElemType.from_int(reader.read_next_byte())

    def get_contents_data_type(self):
        struct = StructureDataType("MarshalSpec", 0)
        if self.native_intrinsic in [CliNativeType.NATIVE_TYPE_ARRAY,
                                       CliNativeType.NATIVE_TYPE_FIXEDARRAY]:
            struct.add(CliNativeTypeDataType(), "ArrayElemTyp")
            if self.array_param_num != CliBlobMarshalSpec.INIT_VALUE:
                struct.add(get_data_type_for_bytes(self.array_param_num_bytes), "ParamNum",
                           "which parameter provides number of elems for this array")
                if self.array_num_elem != CliBlobMarshalSpec.INIT_VALUE:
                    struct.add(get_data_type_for_bytes(self.array_num_elem_bytes), "NumElem",
                               "number of elements or additional elements")

        elif self.native_intrinsic == CliNativeType.NATIVE_TYPE_FIXEDSYSSTRING:
            struct.add(BYTE, "Fixed String Identifier", "")

        elif self.native_intrinsic == CliNativeType.NATIVE_TYPE_SAFEARRAY:
            struct.add(CliSafeArrayElemTypeDataType(), "ElemType", "Type")

        elif self.native_intrinsic == CliNativeType.NATIVE_TYPE_CUSTOMMARSHALER:
            if self.custom_marshaller_cookie != "":
                struct.add(UTF8, len(self.custom_marshaller_guid_or_type_name), "",
                           "GUID or Type Name")
                struct.add(UTF8, len(self.custom_marshaller_guid_or_type_name), "",
                           "Type Name")
                struct.add(UTF8, len(self.custom_marshaller_cookie), "", "Cookie")

        return struct

    def get_contents_name(self):
        return "MarshalSpec"

    def get_contents_comment(self):
        return "Defines a native type for marshalling between managed/unmanaged code"

    def get_representation(self):
        return f"BLOB ({self.get_contents_data_type().get_display_name()})"
```

Please note that this is just an equivalent translation of the given Java code into Python. It may not be exactly identical, as some details might have been lost in translation (e.g., comments).