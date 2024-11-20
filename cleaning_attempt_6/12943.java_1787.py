class BitFieldDBDataTypeTest:
    def __init__(self):
        self.data_mgr = None

    def setup(self):
        if not hasattr(BitFieldDBDataTypeTest, 'data_mgr'):
            self.data_mgr = StandAloneDataTypeManager("dummyDTM")
            self.data_mgr.start_transaction("Test")

    @staticmethod
    def test_get_id_and_get_data_type_from_id(packed_bit_field_data_type):
        BitFieldDBDataType.bit_field_data_type = packed_bit_field_data_type

        bit_field_data_type = data_mgr.resolve(packed_bit_field_data_type, None)
        id = BitFieldDBDataType.get_id(bit_field_data_type)

        # The only thing which is preserved is the bitSize, storageSize and bitOffset/Shift
        bit_field_data_type = BitFieldDBDataType.get_bit_field_data_type(id, data_mgr)

        assert packed_bit_field_data_type.bit_size == bit_field_data_type.bit_size
        assert packed_bit_field_data_type.declared_bit_size == bit_field_data_type.declared_bit_size
        assert packed_bit_field_data_type.bit_offset == bit_field_data_type.bit_offset
        assert packed_bit_field_data_type.storage_size == bit_field_data_type.storage_size

    def test_round_trip(self):
        self.setup()

        # non-standard integer base types
        BitFieldDBDataTypeTest.test_get_id_and_get_data_type_from_id(BitFieldDBDataType(CharDataType.dataType, 1, 4))
        BitFieldDBDataTypeTest.test_get_id_and_get_data_type_from_id(BitFieldDBDataType(CharDataType.dataType, 2, 6))
        BitFieldDBDataTypeTest.test_get_id_and_get_data_type_from_id(BitFieldDBDataType(ShortDataType.dataType, 3, 2))
        BitFieldDBDataTypeTest.test_get_id_and_get_data_type_from_id(BitFieldDBDataType(UnsignedShortDataType.dataType, 4, 4))
        BitFieldDBDataTypeTest.test_get_id_and_get_data_type_from_id(BitFieldDBDataType(IntegerDataType.dataType, 5, 7))
        BitFieldDBDataTypeTest.test_get_id_and_get_data_type_from_id(BitFieldDBDataType(UnsignedIntegerDataType.dataType, 14, 2))
        BitFieldDBDataTypeTest.test_get_id_and_get_data_type_from_id(BitFieldDBDataType(LongDataType.dataType, 27, 2))
        BitFieldDBDataTypeTest.test_get_id_and_get_data_type_from_id(BitFieldDBDataType(UnsignedLongDataType.dataType, 6, 0))
        BitFieldDBDataTypeTest.test_get_id_and_get_data_type_from_id(BitFieldDBDataType(LongLongDataType.dataType, 6, 2))
        BitFieldDBDataTypeTest.test_get_id_and_get_data_type_from_id(BitFieldDBDataType(UnsignedLongLongDataType.dataType, 6, 2))

        # TypeDef base types
        foo = TypedefDataType("foo", IntegerDataType.dataType)
        BitFieldDBDataTypeTest.test_get_id_and_get_data_type_from_id(BitFieldDBDataType(foo, 6, 3))

        # Enum base types
        fum = EnumDataType("fum", 4)
        fum.add("A", 1)
        BitFieldDBDataTypeTest.test_get_id_and_get_data_type_from_id(BitFieldDBDataType(fum, 6, 2))
