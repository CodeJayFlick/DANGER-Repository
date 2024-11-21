import unittest

class CompositeZeroArrayTest(unittest.TestCase):

    def setUp(self):
        self.data_mgr = None

    def get_data_type_manager(self):
        if not self.data_mgr:
            data_org = DataOrganizationImpl().get_default_organization(None)
            DataOrganizationTestUtils.init_data_organization_32_bit_mips(data_org)
            self.data_mgr = create_data_type_manager("test", data_org)

        return self.data_mgr

    def test_structure_zero_array_s1(self):
        struct = get_structure("zeroArrayStruct1")
        assert_expected_composite(struct, "/zeroArrayStruct1\n" +
                                   "pack()\n" +
                                   "Structure zeroArrayStruct1 {\n" +
                                   "   0 int 4 a \"\"\n" +
                                   "   4 char[2] 2 a1 \"\"\n" +
                                   "   6 char[0] 0 x \"\"\n" +
                                   "   8 int[0] 0 y \"\"\n" +
                                   "   8 int 4 b \"\"\n" +
                                   "}\n" +
                                   "Size = 12 Actual Alignment = 4")

    def test_structure_zero_array_s2(self):
        struct = get_structure("zeroArrayStruct2")
        assert_expected_composite(struct, "/zeroArrayStruct2\n" +
                                   "pack()\n" +
                                   "Structure zeroArrayStruct2 {\n" +
                                   "   0 int 4 a \"\"\n" +
                                   "   4 char[2] 2 a1 \"\"\n" +
                                   "   6 char[0] 0 x \"\"\n" +
                                   "   8 int[0] 0 y \"\"\n" +
                                   "}\n" +
                                   "Size = 8 Actual Alignment = 4")

    def test_structure_zero_array_s3(self):
        struct = get_structure("zeroArrayStruct3")
        assert_expected_composite(struct, "/zeroArrayStruct3\n" +
                                   "pack()\n" +
                                   "Structure zeroArrayStruct3 {\n" +
                                   "   0 int 4 a \"\"\n" +
                                   "   4 zeroArrayStruct2 8 s \"\"\n" +
                                   "}\n" +
                                   "Size = 12 Actual Alignment = 4")

    def test_structure_zero_array_u1(self):
        union = get_union("zeroArrayUnion1")
        assert_expected_composite(union, "/zeroArrayUnion1\n" +
                                   "pack()\n" +
                                   "Union zeroArrayUnion1 {\n" +
                                   "   0 int 4 a \"\"\n" +
                                   "   0 char[2] 2 a1 \"\"\n" +
                                   "   0 char[0] 0 x \"\"\n" +
                                   "   0 int[0] 0 y \"\"\n" +
                                   "   0 int 4 b \"\"\n" +
                                   "}\n" +
                                   "Size = 4 Actual Alignment = 4")

    def test_structure_zero_array_u2(self):
        union = get_union("zeroArrayUnion2")
        assert_expected_composite(union, "/zeroArrayUnion2\n" +
                                   "pack()\n" +
                                   "Union zeroArrayUnion2 {\n" +
                                   "   0 int 4 a \"\"\n" +
                                   "   0 char[2] 2 a1 \"\"\n" +
                                   "   0 char[0] 0 x \"\"\n" +
                                   "   0 int[0] 0 y \"\"\n" +
                                   "}\n" +
                                   "Size = 4 Actual Alignment = 4")

    def test_structure_zero_array_u3(self):
        union = get_union("zeroArrayUnion3")
        assert_expected_composite(union, "/zeroArrayUnion3\n" +
                                   "pack()\n" +
                                   "Union zeroArrayUnion3 {\n" +
                                   "   0 int 4 a \"\"\n" +
                                   "   0 zeroArrayStruct2 8 s \"\"\n" +
                                   "}\n" +
                                   "Size = 8 Actual Alignment = 4")

if __name__ == '__main__':
    unittest.main()
