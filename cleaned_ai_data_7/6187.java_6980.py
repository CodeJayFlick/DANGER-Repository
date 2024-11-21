import unittest
from ghidra.app.merge.datatypes import *
from ghidra.program.database import ProgramDB
from ghidra.util.exception import DuplicateNameException
from ghidra.util.task import TaskMonitorAdapter

class TestCategoryMergeUseForAll(unittest.TestCase):

    def test_category_do_not_use_for_all(self):
        mtf = MTF()
        program_modifier_listener = ProgramModifierListener()

        # modify latest
        transaction_id = 0
        misc_cat = program.get_data_type_manager().get_category(CategoryPath("/MISC"))
        cat1 = program.get_data_type_manager().get_category(CategoryPath("/Category1"))
        cat3 = program.get_data_type_manager().get_category(CategoryPath("/Category1/Category2/Category3"))

        try:
            misc_cat.set_name("My Misc")
            cat1.move_category(cat3, TaskMonitorAdapter.DUMMY_MONITOR)
        except DuplicateNameException as e:
            self.fail(f"Got duplicate name exception! {e.message}")
        except InvalidNameException as e:
            self.fail(f"Got invalid name exception! {e.message}")

        finally:
            program.end_transaction(transaction_id)

        # choose My program
        execute_merge()
        resolve_category_conflict(DataTypeMergeManager.OPTION_MY, False, "/Category1/Category2/Category3")
        wait_for_merge_completion()

        root = result_program.get_data_type_manager().get_category(CategoryPath.ROOT)
        self.assertIsNone(root.get_category("MISC"))
        self.assertIsNotNone(root.get_category("My Misc"))

    def test_category_use_for_all_pick_latest(self):
        mtf = MTF()
        program_modifier_listener = ProgramModifierListener()

        # modify latest
        transaction_id = 0
        misc_cat = program.get_data_type_manager().get_category(CategoryPath("/MISC"))
        cat1 = program.get_data_type_manager().get_category(CategoryPath("/Category1"))
        cat3 = program.get_data_type_manager().get_category(CategoryPath("/Category1/Category2/Category3"))

        try:
            misc_cat.set_name("My Misc")
            cat1.move_category(cat3, TaskMonitorAdapter.DUMMY_MONITOR)
        except DuplicateNameException as e:
            self.fail(f"Got duplicate name exception! {e.message}")
        except InvalidNameException as e:
            self.fail(f"Got invalid name exception! {e.message}")

        finally:
            program.end_transaction(transaction_id)

        # choose My program
        execute_merge()
        resolve_category_conflict(CategoryMergePanel, CategoryConflictPanel, DataTypeMergeManager.OPTION_MY, True)
        wait_for_merge_completion()

        root = result_program.get_data_type_manager().get_category(CategoryPath.ROOT)
        self.assertIsNone(root.get_category("MISC"))
        self.assertIsNotNone(root.get_category("Some Other Misc"))

    def test_category_use_for_all_pick_my(self):
        mtf = MTF()
        program_modifier_listener = ProgramModifierListener()

        # modify latest
        transaction_id = 0
        misc_cat = program.get_data_type_manager().get_category(CategoryPath("/MISC"))
        cat1 = program.get_data_type_manager().get_category(CategoryPath("/Category1"))
        cat3 = program.get_data_type_manager().get_category(CategoryPath("/Category1/Category2/Category3"))

        try:
            misc_cat.set_name("My Misc")
            cat1.move_category(cat3, TaskMonitorAdapter.DUMMY_MONITOR)
        except DuplicateNameException as e:
            self.fail(f"Got duplicate name exception! {e.message}")
        except InvalidNameException as e:
            self.fail(f"Got invalid name exception! {e.message}")

        finally:
            program.end_transaction(transaction_id)

        # choose My program
        execute_merge()
        resolve_category_conflict(CategoryMergePanel, CategoryConflictPanel, DataTypeMergeManager.OPTION_MY, True)
        wait_for_merge_completion()

        root = result_program.get_data_type_manager().get_category(CategoryPath.ROOT)
        self.assertIsNone(root.get_category("MISC"))
        self.assertIsNotNone(root.get_category("Some Other Misc"))

    def test_category_use_for_all_pick_original(self):
        mtf = MTF()
        program_modifier_listener = ProgramModifierListener()

        # modify latest
        transaction_id = 0
        misc_cat = program.get_data_type_manager().get_category(CategoryPath("/MISC"))
        cat1 = program.get_data_type_manager().get_category(CategoryPath("/Category1"))
        cat3 = program.get_data_type_manager().get_category(CategoryPath("/Category1/Category2/Category3"))

        try:
            misc_cat.set_name("My Misc")
            cat1.move_category(cat3, TaskMonitorAdapter.DUMMY_MONITOR)
        except DuplicateNameException as e:
            self.fail(f"Got duplicate name exception! {e.message}")
        except InvalidNameException as e:
            self.fail(f"Got invalid name exception! {e.message}")

        finally:
            program.end_transaction(transaction_id)

        # choose My program
        execute_merge()
        resolve_category_conflict(CategoryMergePanel, CategoryConflictPanel, DataTypeMergeManager.OPTION_ORIGINAL, True)
        wait_for_merge_completion()

        root = result_program.get_data_type_manager().get_category(CategoryPath.ROOT)
        self.assertIsNotNone(root.get_category("MISC"))
        self.assertIsNone(root.get_category("Some Other Misc"))

    def test_datatype_do_not_use_for_all(self):
        mtf = MTF()
        program_modifier_listener = ProgramModifierListener()

        # modify latest
        transaction_id = 0
        misc_cat = program.get_data_type_manager().get_category(CategoryPath("/MISC"))
        cat1 = program.get_data_type_manager().get_category(CategoryPath("/Category1"))
        cat3 = program.get_data_type_manager().get_category(CategoryPath("/Category1/Category2/Category3"))

        try:
            misc_cat.set_name("My Misc")
            cat1.move_category(cat3, TaskMonitorAdapter.DUMMY_MONITOR)
        except DuplicateNameException as e:
            self.fail(f"Got duplicate name exception! {e.message}")
        except InvalidNameException as e:
            self.fail(f"Got invalid name exception! {e.message}")

        finally:
            program.end_transaction(transaction_id)

        # choose My program
        execute_merge()
        resolve_category_conflict(CategoryMergePanel, CategoryConflictPanel, DataTypeMergeManager.OPTION_MY, False)
        wait_for_merge_completion()

        root = result_program.get_data_type_manager().get_category(CategoryPath.ROOT)
        self.assertIsNone(root.get_category("MISC"))
        self.assertIsNotNone(root.get_category("Some Other Misc"))

if __name__ == '__main__':
    unittest.main()
