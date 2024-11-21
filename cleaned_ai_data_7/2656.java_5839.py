import unittest
from ghidra.util import InvalidNameException, DuplicateNameException
from ghidra.program.model.data import StructureDataType
from ghidra.program.model.lang import LanguageID
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.undotransaction import UndoableTransaction

class DBTraceDataTypeManagerTest(unittest.TestCase):
    def setUp(self):
        self.toy_language = DefaultLanguageService().get_language(LanguageID("Toy:BE:64:default"))
        self.trace = DBTrace("Testing", self.toy_language.get_default_compiler_spec(), None)
        self.dtm = self.trace.get_data_type_manager()

    def tearDown(self):
        self.trace.release(None)

    def get_test_data_type(self):
        mine = StructureDataType(new_category_path("/Some/Path"), "TestType", 0)
        mine.add(UnsignedLongLongDataType.data_type, "f0", None)
        mine.add(UnsignedLongDataType.data_type, "f8", None)
        mine.add(UnsignedLongDataType.data_type, "fc", None)
        return mine

    def get_test_data_type_b(self):
        mine = StructureDataType(new_category_path("/Some/Path"), "TestTypeB", 0)
        mine.add(UnsignedLongDataType.data_type, "f0", None)
        mine.add(UnsignedLongLongDataType.data_type, "f4", None)
        mine.add(UnsignedLongDataType.data_type, "fc", None)
        return mine

    def test_get_name(self):
        self.assertEqual("Testing", self.dtm.get_name())

    def test_set_name(self):
        try:
            with UndoableTransaction(self.trace, "Testing", True) as tid:
                self.dtm.set_name("Another name")
        except InvalidNameException:
            pass
        self.assertEqual("Another name", self.trace.get_name())

    def test_add_source_archive(self):
        mine = self.get_test_data_type()
        mine_path = mine.get_data_type_path()
        tmp_dir = Files.create_temp_directory("test")
        archive_file = tmp_dir.resolve("test.gdt").to_file()
        dtm2 = FileDataTypeManager().create_file_archive(archive_file)
        try:
            with UndoableTransaction(dtm2, "Testing", True) as tid:
                dtm2.add_data_type(mine, DataTypeConflictHandler.DEFAULT_HANDLER)
        except IOException:
            pass
        got = dtm2.get_data_type(mine_path)

        try:
            with UndoableTransaction(self.trace, "Testing", True) as tid:
                self.dtm.add_data_type(got, DataTypeConflictHandler.DEFAULT_HANDLER)
        except IOException:
            pass

    def test_add_get(self):
        mine = self.get_test_data_type()
        mine_path = mine.get_data_type_path()
        try:
            with UndoableTransaction(self.trace, "Testing", True) as tid:
                self.dtm.add_data_type(mine, DataTypeConflictHandler.REPLACE_HANDLER)
        except IOException:
            pass

        got = self.dtm.get_data_type(mine_path)
        self.assertEqual(str(mine), str(got))

    def test_add_remove_undo_then_get(self):
        mine = self.get_test_data_type()
        mine_path = mine.get_data_type_path()

        try:
            with UndoableTransaction(self.trace, "Testing", True) as tid:
                self.dtm.add_data_type(mine, DataTypeConflictHandler.REPLACE_HANDLER)
        except IOException:
            pass

        got = self.dtm.get_data_type(mine_path)
        self.assertEqual(str(mine), str(got))

        try:
            with UndoableTransaction(self.trace, "To Undo", True) as tid:
                self.dtm.remove(got, ConsoleTaskMonitor())
        except IOException:
            pass

        self.assertIsNone(self.dtm.get_data_type(mine_path))

        self.trace.undo()

        got = self.dtm.get_data_type(mine_path)
        self.assertEqual(str(mine), str(got))

    def test_change_data_type(self):
        mine = self.get_test_data_type()
        mine_path = mine.get_data_type_path()

        try:
            with UndoableTransaction(self.trace, "Testing", True) as tid:
                self.dtm.add_data_type(mine, DataTypeConflictHandler.REPLACE_HANDLER)

                got = self.dtm.get_data_type(mine_path)
                got.replace(1, LongDataType.data_type, 4, "sf4", "changed to signed")
        except IOException:
            pass

    def test_replace_data_type(self):
        mine_a = self.get_test_data_type()
        mine_b = self.get_test_data_type_b()

        try:
            with UndoableTransaction(self.trace, "Testing", True) as tid:
                self.dtm.add_data_type(mine_a, DataTypeConflictHandler.REPLACE_HANDLER)

                got = self.dtm.get_data_type(mine_a.get_data_type_path())
                self.dtm.replace_data_type(got, mine_b, True)
        except IOException:
            pass

    def test_move_data_type(self):
        try:
            with UndoableTransaction(self.trace, "Testing", True) as tid:
                got = self.dtm.add_data_type(self.get_test_data_type(), DataTypeConflictHandler.REPLACE_HANDLER)

                got.set_category_path(new_category_path("/Another/Path"))
        except IOException:
            pass

    def test_rename_data_type(self):
        try:
            with UndoableTransaction(self.trace, "Testing", True) as tid:
                got = self.dtm.add_data_type(self.get_test_data_type(), DataTypeConflictHandler.REPLACE_HANDLER)

                got.set_name("RenamedType")
        except IOException:
            pass

    def test_create_category(self):
        category = None
        try:
            with UndoableTransaction(self.trace, "Testing", True) as tid:
                category = self.dtm.create_category(new_category_path("/Another/Path"))
        except DuplicateNameException:
            pass
        self.assertEqual(category, self.dtm.get_category(new_category_path("/Another/Path")))

    def test_move_category(self):
        to_move = None

        try:
            with UndoableTransaction(self.trace, "Testing", True) as tid:
                category = self.dtm.create_category(new_category_path("/Another/Path"))
                to_move = self.dtm.create_category(new_category_path("/MoveMe"))

                category.move_category(to_move, ConsoleTaskMonitor())
        except DuplicateNameException:
            pass
        self.assertEqual(to_move, self.dtm.get_category(new_category_path("/Another/Path/MoveMe")))

    def test_rename_category(self):
        try:
            with UndoableTransaction(self.trace, "Testing", True) as tid:
                category = self.dtm.create_category(new_category_path("/Another/Path"))
                category.set_name("Renamed")
        except DuplicateNameException:
            pass
        self.assertEqual(category, self.dtm.get_category(new_category_path("/Another/Renamed")))

    def test_remove_category(self):
        try:
            with UndoableTransaction(self.trace, "Testing", True) as tid:
                category = self.dtm.create_category(new_category_path("/Another/Path"))
        except DuplicateNameException:
            pass
        self.assertEqual(category, self.dtm.get_category(new_category_path("/Another/Path")))

        try:
            with UndoableTransaction(self(trace), "Testing", True) as tid:
                self.dtm.get_category(new_category_path("/Another")).remove_empty_category("Path", ConsoleTaskMonitor())
        except IOException:
            pass
        self.assertIsNone(self.dtm.get_category(new_category_path("/Another/Path")))

if __name__ == "__main__":
    unittest.main()
