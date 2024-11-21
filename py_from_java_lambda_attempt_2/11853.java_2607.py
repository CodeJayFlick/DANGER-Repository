Here is the translation of the given Java code into equivalent Python:

```Python
class BitFieldDBDataType:
    def __init__(self, base_data_type: 'DataType', bit_size: int, bit_offset: int):
        super().__init__(base_data_type, bit_size, bit_offset)

    @staticmethod
    def get_base_type_encoded_field(bitfield_dt: 'BitFieldDataType', data_type_kind: 'BaseDatatypeKind') -> int:
        nominal_storage_size = BitFieldDBDataType.get_minimum_storage_size(bitfield_dt.bit_size)
        extra_storage_used = bitfield_dt.storage_size > nominal_storage_size
        return (data_type_kind.id << 5) | (extra_storage_used * 0x10)

    @staticmethod
    def get_bit_field_data_type(id: int, dtm: 'DataTypeManagerDB') -> 'BitFieldDataType':
        bit_size = id & 0xff
        bit_offset = (id >> BitFieldDBDataType.BIT_OFFSET_SHIFT) & 0xff
        base_type_info = (id >> BitFieldDBDataType.BASE_TYPE_SHIFT) & 0xff

        data_type_kind = BaseDatatypeKind.get_kind((base_type_info >> 5) & 3)

        if data_type_kind != BaseDatatypeKind.NONE and id > BitFieldDBDataType.MAX_DATATYPE_INDEX:
            return None

        base_data_type = None
        data_type_index = (id >> BitFieldDBDataType.DATATYPE_INDEX_SHIFT) & BitFieldDBDataType.MAX_DATATYPE_INDEX
        if data_type_kind != BaseDatatypeKind.NONE and data_type_index != BitFieldDBDatabase.MAX_DATATYPE_ID:
            if data_type_kind == BaseDatatypeKind.TYPEDEF:
                base_data_type = BitFieldDBDataType.get_typedef(data_type_index, dtm)
            elif data_type_kind == BaseDatatypeKind.ENUM:
                base_data_type = BitFieldDBDataType.get_enum(data_type_index, dtm)
            else:
                base_data_type = BitFieldDBDatabase.get_integer_type(data_type_index, dtm)

        try:
            if base_data_type is None:
                # use integer datatype on failure
                base_data_type = IntegerDataType.dataType.clone(dtm)
            return BitFieldDBDataType(base_data_type, bit_size, bit_offset)
        except InvalidDataTypeException as e:
            return None

    @staticmethod
    def get_resolved_data_type_index(data_type: 'DataType', dtm: 'DataTypeManagerDB') -> int:
        data_type_id = dtm.get_id(data_type)
        if data_type_id == BitFieldDBDatabase.NULL_DATATYPE_ID:
            return BitFieldDBDatabase.NULL_DATATYPE_ID
        return data_type_id & ~BitFieldDBDatabase.ID_TO_INDEX_MASK

    @staticmethod
    def get_typedef(type_def_index: int, dtm: 'DataTypeManager') -> 'TypeDef':
        data_type_id = (type_def_index << BitFieldDBDatabase.TYPEDEF_SHIFT) | 0x1
        data_type = dtm.get_data_type(data_type_id)
        if not isinstance(data_type, TypeDef):
            return None

        type_def_dt = TypeDef(data_type)
        base_data_type = type_def_dt.base_data_type
        if isinstance(base_data_type, Enum:
            # TODO: how restrictive should we be on matching enum size?
            return type_def_dt
        elif isinstance(base_data_type, AbstractIntegerDataType):
            return type_def_dt
        else:
            return None  # unsupported typedef

    @staticmethod
    def get_enum(enum_index: int, dtm: 'DataTypeManager') -> 'Enum':
        data_type_id = (enum_index << BitFieldDBDatabase.ENUM_SHIFT) | 0x2
        data_type = dtm.get_data_type(data_type_id)
        if not isinstance(data_type, Enum):
            return None

    @staticmethod
    def get_integer_type(int_type_index: int, dtm: 'DataTypeManager') -> 'AbstractIntegerDataType':
        data_type_id = (int_type_index << BitFieldDBDatabase.INTEGER_SHIFT) | 0x3
        data_type = dtm.get_data_type(data_type_id)
        if not isinstance(data_type, AbstractIntegerDataType):
            return None

class BaseDatatypeKind:
    NONE = 0
    TYPEDEF = 1
    ENUM = 2
    INTEGER = 3

    @staticmethod
    def get_kind(value: int) -> 'BaseDatatypeKind':
        for kind in values():
            if kind.id == value:
                return kind
        return BaseDatatypeKind.NONE