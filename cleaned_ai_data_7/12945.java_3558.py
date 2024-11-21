import unittest
from ghidra_appdb import *

class UnionDBTest(unittest.TestCase):

    def setUp(self):
        self.data_mgr = StandAloneDataTypeManager("dummydataMgr")
        # default data organization is little-Endian
        # default BitFieldPackingImpl uses gcc conventions

        self.data_mgr.start_transaction("Test")

        self.union = create_union("TestUnion")
        self.union.add(new ByteDataType(), "field1", "Comment1")
        self.union.add(new WordDataType(), None, "Comment2")
        self.union.add(new DWordDataType(), "field3", None)
        self.union.add(new ByteDataType(), "field4", "Comment4")

    def transition_to_big_endian(self):
        union_clone = (self.union.clone(None))
        data_org = self.data_mgr.get_data_organization()
        data_org.set_big_endian(True)

        # re-resolve with modified endianness
        self.union = self.data_mgr.resolve(union_clone, None)

    def create_union(self, name):
        return UnionDataType(name)

    def test_add(self):
        self.assertEqual(4, self.union.get_length())
        self.assertEqual(4, self.union.get_num_components())

        dtcs = self.union.get_components()
        self.assertEqual(4, len(dtcs))

        dtc = self.union.get_component(3)
        self.assertEqual("field4", dtc.get_field_name())

    def test_add2(self):
        struct = create_structure("struct_1", 0)
        struct.add(new ByteDataType())
        struct.add(new StringDataType(), 10)

        self.union.add(struct)
        self.assertEqual(11, self.union.get_length())

    # ... and so on for the rest of your tests
