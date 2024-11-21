Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra_program_database import ProgramDB
from enum_data_type import EnumDataType
from category import Category
from data_type_manager import DataTypeManagerDB

class TestEnum(unittest.TestCase):

    def setUp(self):
        self.program = create_default_program("Test", "TOY")
        self.data_mgr = self.program.get_data_type_manager()
        transaction_id = self.program.start_transaction("Test")

    def tearDown(self):
        self.program.end_transaction(transaction_id, False)
        self.program.release()

    def test_create_enum(self):
        enumm = EnumDataType("Color", 1)
        enumm.add("Red", 0)
        enumm.add("Green", 1)
        enumm.add("Blue", 2)

        root_category = self.data_mgr.get_root_category()
        category = root_category.create_category("enumms")
        enumm.set_category_path(category.get_category_path())
        enum_dt = self.data_mgr.resolve(enumm, None)

        assert enum_dt is not None

        self.assertEqual("Color", enum_dt.name)
        self.assertEqual(0, enum_dt.value("Red"))
        self.assertEqual(1, enum_dt.value("Green"))
        self.assertEqual(2, enum_dt.value("Blue"))

    def test_remove_value(self):
        enumm = EnumDataType("Color", 1)
        enumm.add("Red", 10)
        enumm.add("Green", 15)
        enumm.add("Blue", 20)

        root_category = self.data_mgr.get_root_category()
        category = root_category.create_category("enumms")
        enumm.set_category_path(category.get_category_path())
        enum_dt = self.data_mgr.resolve(enumm, None)

        assertArrayEquals([0, 1, 2], enumm.values)
        assertEquals(4, enumm.count())

        enum_dt.remove("Green")

    def test_add_value(self):
        enumm = EnumDataType("Color", 1)
        enumm.add("Red", 10)
        enumm.add("Green", 15)
        enumm.add("Blue", 20)

        root_category = self.data_mgr.get_root_category()
        category = root_category.create_category("enumms")
        enumm.set_category_path(category.get_category_path())

        enum_dt = self.data_mgr.resolve(enumm, None)

        enum_dt.add("Purple", 7)
        assertEquals(5, enum_dt.count())
        assertEquals(7, enum_dt.value("Purple"))
        assertEquals(2, enum_dt.value("Blue"))

    def test_edit_value(self):
        enumm = EnumDataType("Color", 1)
        enumm.add("Red", 10)
        enumm.add("Green", 15)
        enumm.add("Blue", 20)

        root_category = self.data_mgr.get_root_category()
        category = root_category.create_category("enumms")
        enumm.set_category_path(category.get_category_path())
        enum_dt = self.data_mgr.resolve(enumm, None)

        domain_obj_listener = DomainObjListener()

    def test_clone_retain_identity(self):
        enumm = EnumDataType("Color", 1)
        enumm.add("Red", 10)
        enumm.add("Green", 15)
        enumm.add("Blue", 20)

        root_category = self.data_mgr.get_root_category()
        category = root_category.create_category("enumms")
        enumm.set_category_path(category.get_category_path())
        enum_dt = self.data_mgr.resolve(enumm, None)

        copy_dt = enum_dt.clone(None)
        assert copy_dt is not None

    def test_copy_no_retain_identity(self):
        enumm = EnumDataType("Color", 1)
        enumm.add("Red", 10)
        enumm.add("Green", 15)
        enumm.add("Blue", 20)

        root_category = self.data_mgr.get_root_category()
        category = root_category.create_category("enumms")
        enumm.set_category_path(category.get_category_path())
        enum_dt = self.data_mgr.resolve(enumm, None)

        copy_dt = enum_dt.copy(None)
        assert copy_dt is not None

    def test_remove_enum(self):
        enumm = EnumDataType("Color", 1)
        enumm.add("Red", 10)
        enumm.add("Green", 15)
        enumm.add("Blue", 20)

        root_category = self.data_mgr.get_root_category()
        category = root_category.create_category("enumms")
        enumm.set_category_path(category.get_category_path())
        enum_dt = self.data_mgr.resolve(enumm, None)

        category.remove(enum_dt, TaskMonitor.DUMMY)
        assert category.get_data_type("Color") is None

    def test_move_enum(self):
        enumm = EnumDataType("Color", 1)
        enumm.add("Red", 10)
        enumm.add("Green", 15)
        enumm.add("Blue", 20)

        root_category = self.data_mgr.get_root_category()
        category = root_category.create_category("enumms")
        enumm.set_category_path(category.get_category_path())
        enum_dt = self.data_mgr.resolve(enumm, None)

        root_category.move_data_type(enum_dt, None)
        assert root_category.get_data_type(enumm.name) is not None
        assert category.get_data_type(enumm.name) is None

    def test_resolve(self):
        enumm = EnumDataType("Color", 1)
        enumm.add("Red", 10)
        enumm.add("Green", 15)
        enumm.add("Blue", 20)

        root_category = self.data_mgr.get_root_category()
        category = root_category.create_category("enumms")
        enumm.set_category_path(category.get_category_path())
        enum_dt = self.data_mgr.resolve(enumm, None)

    def test_replace(self):
        enumm = EnumDataType("Color", 1)
        enumm.add("Red", 10)
        enumm.add("Green", 15)
        enumm.add("Blue", 20)

        root_category = self.data_mgr.get_root_category()
        category = root_category.create_category("enumms")
        enumm.set_category_path(category.get_category_path())
        enum_dt = self.data_mgr.resolve(enumm, None)

        my_enum = EnumDataType("my enum", 1)
        my_enum.add("My red", 0)
        my_enum.add("My Green", 5)
        my_enum.add("My Blue", 10)
        my_enum.add("Purple", 20)

        enum_dt.replace_with(my_enum)

    def test_is_equivalent(self):
        enumm = EnumDataType("Color", 1)
        enumm.add("Red", 10)
        enumm.add("Green", 15)
        enumm.add("Blue", 20)

        root_category = self.data_mgr.get_root_category()
        category = root_category.create_category("enumms")
        enumm.set_category_path(category.get_category_path())
        enum_dt = self.data_mgr.resolve(enumm, None)

    def test_name_sort(self):
        my_enum = EnumDataType("Color", 1)
        my_enum.add("Red", 20)
        my_enum.add("Pink", 20)
        my_enum.add("Salmon", 20)
        my_enum.add("Green", 1)
        my_enum.add("Another Green", 1)
        my_enum.add("Blue", 3)

    names = my_enum.names
    self.assertEqual("Another Green", names[0])
    self.assertEqual("Green", names[1])
    self.assertEqual("Blue", names[2])
    self.assertEqual("Pink", names[3])
    self.assertEqual("Red", names[4])
    self.assertEqual("Salmon", names[5])

if __name__ == "__main__":
    unittest.main()
```

Please note that the Python code does not exactly translate the Java code, but it should give you a good starting point.