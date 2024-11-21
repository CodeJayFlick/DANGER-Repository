import unittest
from ghidra.program.database import ProgramDB
from ghidra.program.model.address import AddressSpace
from ghidra.util.exception import DuplicateNameException, InvalidInputException

class ExternalManagerDBTest(unittest.TestCase):

    def setUp(self):
        self.program = create_default_program("test_name", "TOY")
        self.space = self.program.getAddressFactory().getDefaultAddressSpace()
        self.ext_mgr = self.program.getExternalManager()
        transaction_id = self.program.startTransaction("Test")

    def tearDown(self):
        if self.program:
            self.program.endTransaction(transaction_id, True)
            self.program.release()

    def addr(self, offset):
        return self.space.getAddress(offset)

    @unittest.skip
    def test_add_ext_location(self):

        loc1 = self.ext_mgr.addExtLocation("ext1", "label0", None, SourceType.USER_DEFINED)
        self.assertEqual("ext1", loc1.getLibraryName())
        self.assertEqual("label0", loc1.getLabel())

        loc2 = self.ext_mgr.addExtLocation("ext1", "label1", self.addr(1000), SourceType.USER_DEFINED)
        self.assertEqual("ext1", loc2.getLibraryName())
        self.assertEqual("label1", loc2.getLabel())

        loc3 = self.ext_mgr.addExtLocation("ext2", "label1", None, SourceType.USER_DEFINED)
        self.assertEqual("ext2", loc3.getLibraryName())
        self.assertEqual("label1", loc3.getLabel())

        loc4 = self.ext_mgr.addExtLocation("ext2", "label2", None, SourceType.USER_DEFINED)

        try:
            self.ext_mgr.addExtLocation("ext2", null, addr(2000), SourceType.USER_DEFINED)
            self.fail()
        except InvalidInputException as e:
            pass

        loc5 = self.ext_mgr.addExtLocation("ext2", null, self.addr(2000), SourceType.USER_DEFINED)

        try:
            self.ext_mgr.addExtLocation("ext1", "label1", addr(1500), SourceType.USER_DEFINED)
            self.fail()
        except InvalidInputException as e:
            pass

        self.ext_mgr.invalidateCache(True)

        names = self.ext_mgr.getExternalLibraryNames()
        self.assertEqual(len(names), 2)
        self.assertEqual(names[0], "ext1")
        self.assertEqual(names[1], "ext2")

        self.assertEqual(loc1, self.ext_mgr.getExtLocation(loc1.getExternalSpaceAddress()))
        self.assertEqual(loc2, self.ext_mgr.getExtLocation(loc2.getExternalSpaceAddress()))
        self.assertEqual(loc3, self.ext_mgr.getExtLocation(loc3.getExternalSpaceAddress()))
        self.assertEqual(loc4, self.ext_mgr.getExtLocation(loc4.getExternalSpaceAddress()))
        self.assertEqual(loc5, self.ext_mgr.getExtLocation(loc5.getExternalSpaceAddress()))

    @unittest.skip
    def test_get_external_locations_by_library_name(self):

        loc1 = self.ext_mgr.addExtLocation("ext1", "label0", None, SourceType.USER_DEFINED)
        loc2 = self.ext_mgr.addExtLocation("ext1", "label1", addr(1000), SourceType.USER_DEFINED)
        loc3 = self.ext_mgr.addExtLocation("ext2", "label1", None, SourceType.USER_DEFINED)
        loc4 = self.ext_mgr.addExtLocation("ext2", "label2", None, SourceType.USER_DEFINED)

        loc5 = self.ext_mgr.addExtLocation("ext2", null, addr(2000), SourceType.USER_DEFINED)

        iter = self.ext_mgr.getExternalLocations("ext2")
        while iter.hasNext():
            location = iter.next()
            if location == loc3:
                break
        else:
            self.fail()

    @unittest.skip
    def test_get_external_locations_by_mem_addr(self):

        loc1 = self.ext_mgr.addExtLocation("ext1", "label0", None, SourceType.USER_DEFINED)
        loc2 = self.ext_mgr.addExtLocation("ext1", "label1", addr(1000), SourceType.USER_DEFINED)
        loc3 = self.ext_mgr.addExtLocation("ext2", "label1", None, SourceType.USER_DEFINED)
        loc4 = self.ext_mgr.addExtLocation("ext2", "label2", None, SourceType.USER_DEFINED)

        loc5 = self.ext_mgr.addExtLocation("ext2", null, addr(2000), SourceType.USER_DEFINED)

        iter = self.ext_mgr.getExternalLocations(addr(2000))
        while iter.hasNext():
            location = iter.next()
            if location == loc5:
                break
        else:
            self.fail()

    @unittest.skip
    def test_get_external_location_by_name(self):

        #loc1 = self.ext_mgr.addExtLocation("ext1", "label0", None, SourceType.USER_DEFINED)
        #loc2 = self.ext_mgr.addExtLocation("ext1", "label1", addr(1000), SourceType.USER_DEFINED)
        #loc3 = self.ext_mgr.addExtLocation("ext2", "label1", None, SourceType.USER_DEFINED)
        #loc4 = self.ext_mgr.addExtLocation("ext2", "label2", None, SourceType.USER_DEFINED)

        loc5 = self.ext_mgr.addExtLocation("ext2", null, addr(2000), SourceType.USER_DEFINED)

        location = self.ext_mgr.getUniqueExternalLocation("ext2", loc5.getLabel())
        self.assertEqual(location, loc5)

    @unittest.skip
    def test_remove_external_location(self):

        loc1 = self.ext_mgr.addExtLocation("ext1", "label0", None, SourceType.USER_DEFINED)
        loc2 = self.ext_mgr.addExtLocation("ext1", "label1", addr(1000), SourceType.USER_DEFINED)
        loc3 = self.ext_mgr.addExtLocation("ext2", "label1", None, SourceType.USER_DEFINED)
        loc4 = self.ext_mgr.addExtLocation("ext2", "label2", None, SourceType.USER_DEFINED)

        loc5 = self.ext_mgr.addExtLocation("ext2", null, addr(2000), SourceType.USER_DEFINED)

        try:
            self.ext_mgr.removeExternalLocation(loc1.getExternalSpaceAddress())
            self.fail()
        except InvalidInputException as e:
            pass

    @unittest.skip
    def test_update_external_program_name(self):

        loc1 = self.ext_mgr.addExtLocation("ext1", "label0", None, SourceType.USER_DEFINED)
        loc2 = self.ext_mgr.addExtLocation("ext1", "label1", addr(1000), SourceType.USER_DEFINED)
        loc3 = self.ext_mgr.addExtLocation("ext2", "label1", None, SourceType.USER_DEFINED)
        loc4 = self.ext_mgr.addExtLocation("ext2", "label2", None, SourceType.USERDEFINED)

        try:
            self.ext_mgr.updateExternalLibraryName("ext2", "ext1", SourceType.USER_DEFINED)
            self.fail()
        except DuplicateNameException as e:
            pass

    @unittest.skip
    def test_set_external_path(self):

        loc1 = self.ext_mgr.addExtLocation("ext1", "label0", None, SourceType.USER_DEFINED)

        try:
            self.ext_mgr.setExternalPath("ext2", "/a/b/c", True)
            self.fail()
        except InvalidInputException as e:
            pass

    @unittest.skip
    def test_set_relative_external_path(self):

        loc1 = self.ext_mgr.addExtLocation("ext1", "label0", None, SourceType.USER_DEFINED)

        try:
            self.ext_mgr.setExternalPath("ext2", "/relative/path/value", True)
            self.fail()
        except InvalidInputException as e:
            pass

    @unittest.skip
    def test_clear_external_path_with_null_value(self):

        loc1 = self.ext_mgr.addExtLocation("ext1", "label0", None, SourceType.USER_DEFINED)

        try:
            self.ext_mgr.setExternalPath("ext2", "/a/b/c", True)
            self.fail()
        except InvalidInputException as e:
            pass

    @unittest.skip
    def test_original_import_name(self):

        loc = self.ext_mgr.addExtLocation("ext1", "foo", addr(1000), SourceType.IMPORTED)

        try:
            loc.setName(loc.getParentNameSpace(), "bar", SourceType.ANALYSIS)
            self.fail()
        except InvalidInputException as e:
            pass

if __name__ == '__main__':
    unittest.main()
