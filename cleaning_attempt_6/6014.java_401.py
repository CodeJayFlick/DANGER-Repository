import unittest
from ghidra.program.model.address import Address
from ghidra.program.model.data import Array, DataType, Pointer32DataType, StringDataType, Structure
from ghidra.program.model.listing import Data


class CreateArrayCmdTest(unittest.TestCase):

    def setUp(self):
        self.program = build_program()
        self.listing = self.program.getListing()

    def tearDown(self):
        pass

    @staticmethod
    def addr(offset):
        return Address(0, offset)

    @staticmethod
    def create_array(element_data_type: DataType, element_length: int) -> Array:
        undefined_area_addr = CreateArrayCmdTest.addr(UNDEFINED_AREA)
        cmd = CreateArrayCmd(undefined_area_addr, 10, element_data_type, element_length)
        cmd.apply_to(self.program)

        data = self.listing.get_data_at(undefined_area_addr)
        assert data is not None
        self.assertTrue(data.is_array())
        dt = data.get_data_type()
        self.assertIsInstance(dt, Array)
        array = dt
        dt = array.get_data_type()
        self.assertIsNotNone(dt)
        self.assertTrue(dt.is_equivalent(element_data_type))

        after_data = self.listing.get_data_after(undefined_area_addr)
        assert after_data is not None
        self.assertFalse(after_data.is_defined())
        self.assertEqual(CreateArrayCmdTest.addr(UNDEFINED_AREA + (10 * element_length)), data.min_address())

        return dt

    @staticmethod
    def create_struct(addr: Address) -> Structure:
        cmd = CreateStructureCmd(addr, 10)
        cmd.apply_to(self.program)

        d = self.listing.get_data_at(addr)
        self.assertTrue(d.is_structure())
        dt = d.get_data_type()
        self.assertIsInstance(dt, Structure)
        self.assertEqual(10, dt.length())

        return dt

    def test_create_undefined_data_array(self):
        create_array(DataType.DEFAULT, 1)

    def test_create_undefined_pointer_array(self):
        pt = Pointer32DataType(DataType.DEFAULT)
        psize = addr(UNDEFINED_AREA).get_pointer_size()
        create_array(pt, psize)

    def test_create_defined_data_array(self):
        create_array(ByteDataType(), 1)

    def test_create_defined_pointer_array(self):
        pt = Pointer32DataType(ByteDataType())
        psize = addr(UNDEFINED_AREA).get_pointer_size()
        create_array(pt, psize)

    def test_create_string_array(self):
        create_array(StringDataType(), 8)

    def test_string_pointer_array(self):
        pt = Pointer32DataType(StringDataType())
        psize = addr(UNDEFINED_AREA).get_pointer_size()
        create_array(pt, psize)

    def test_create_struct_array(self):
        addr = CreateArrayCmdTest.addr(UNDEFINED_AREA)
        sdt = self.create_struct(addr)
        create_array(sdt, sdt.length())

    def test_create_array_array(self):
        adt = create_array(ByteDataType(), 1)
        create_array(adt, adt.length())

    def test_create_array_pointer_array(self):
        adt = create_array(ByteDataType(), 1)
        pt = Pointer32DataType(adt)
        psize = addr(UNDEFINED_AREA).get_pointer_size()
        create_array(pt, psize)

    def test_create_struct_pointer_array(self):
        addr = CreateArrayCmdTest.addr(UNDEFINED_AREA)
        sdt = self.create_struct(addr)
        pt = Pointer32DataType(sdt)
        psize = addr.get_pointer_size()
        create_array(pt, psize)


if __name__ == '__main__':
    unittest.main()

class ByteDataType(DataType):
    pass

class StringDataType(DataType):
    pass
