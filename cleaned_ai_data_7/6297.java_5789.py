import unittest
from ghidra_framework_options import Options
from ghidra_program_model_data import DataTypeManager
from ghidra_util_exception import DuplicateNameException, UsrException

class StructureEditorProviderTest(unittest.TestCase):

    def setUp(self):
        self.options = Options()
        self.data_type_manager = DataTypeManager()

    @unittest.skip("This test is not implemented yet.")
    def testDataTypeChanged(self):
        try:
            # Add the s1 data type so that we can undo its add.
            start_transaction("Structure Editor Test Initialization")
            try:
                dt = (Structure) pgm_test_cat.add_data_type(s1, DataTypeConflictHandler.DEFAULT_HANDLER)
            finally:
                end_transaction(commit)

            assert not dt.is_equivalent(model.view_composite)

        except Exception as e:
            self.fail(e.getMessage())

    @unittest.skip("This test is not implemented yet.")
    def testModifiedDtAndProgramRestored(self):
        try:
            # Add the s1 data type so that we can undo its add.
            start_transaction("Structure Editor Test Initialization")
            try:
                dt = (Structure) pgm_test_cat.add_data_type(s1, DataTypeConflictHandler.DEFAULT_HANDLER)
            finally:
                end_transaction(commit)

            assert not complex_structure.is_equivalent(model.view_composite)

        except Exception as e:
            self.fail(e.getMessage())

    @unittest.skip("This test is not implemented yet.")
    def testProgramRestoreRemovesEditedDt(self):
        try:
            # Add the s1 data type so that we can undo its add.
            start_transaction("Structure Editor Test Initialization")
            try:
                dt = (Structure) pgm_test_cat.add_data_type(s1, DataTypeConflictHandler.DEFAULT_HANDLER)
            finally:
                end_transaction(commit)

            assert not complex_structure.is_equivalent(model.view_composite)

        except Exception as e:
            self.fail(e.getMessage())

    @unittest.skip("This test is not implemented yet.")
    def testProgramRestoreRemovesEditedDtComp(self):
        try:
            # Add the s1 data type so that we can undo its add.
            start_transaction("Structure Editor Test Initialization")
            try:
                dt = (Structure) pgm_test_cat.add_data_type(s1, DataTypeConflictHandler.DEFAULT_HANDLER)
            finally:
                end_transaction(commit)

            assert not complex_structure.is_equivalent(model.view_composite)

        except Exception as e:
            self.fail(e.getMessage())

    @unittest.skip("This test is not implemented yet.")
    def testProgramRestoreRemovesEditedComponentDtYes(self):
        try:
            # Add the s1 data type so that we can undo its add.
            start_transaction("Structure Editor Test Initialization")
            try:
                dt = (Structure) pgm_test_cat.add_data_type(s1, DataTypeConflictHandler.DEFAULT_HANDLER)
            finally:
                end_transaction(commit)

            assert not complex_structure.is_equivalent(model.view_composite)

        except Exception as e:
            self.fail(e.getMessage())

    @unittest.skip("This test is not implemented yet.")
    def testProgramRestoreRemovesEditedComponentDtNo(self):
        try:
            # Add the s1 data type so that we can undo its add.
            start_transaction("Structure Editor Test Initialization")
            try:
                dt = (Structure) pgm_test_cat.add_data_type(s1, DataTypeConflictHandler.DEFAULT_HANDLER)
            finally:
                end_transaction(commit)

            assert not complex_structure.is_equivalent(model.view_composite)

        except Exception as e:
            self.fail(e.getMessage())

    @unittest.skip("This test is not implemented yet.")
    def testUnModifiedDtAndProgramRestored(self):
        try:
            # Add the s1 data type so that we can undo its add.
            start_transaction("Structure Editor Test Initialization")
            try:
                dt = (Structure) pgm_test_cat.add_data_type(s1, DataTypeConflictHandler.DEFAULT_HANDLER)
            finally:
                end_transaction(commit)

            assert not complex_structure.is_equivalent(model.view_composite)

        except Exception as e:
            self.fail(e.getMessage())

    @unittest.skip("This test is not implemented yet.")
    def testCloseEditorProviderUnmodified(self):
        try:
            # Add the s1 data type so that we can undo its add.
            start_transaction("Structure Editor Test Initialization")
            try:
                dt = (Structure) pgm_test_cat.add_data_type(s1, DataTypeConflictHandler.DEFAULT_HANDLER)
            finally:
                end_transaction(commit)

            assert not complex_structure.is_equivalent(model.view_composite)

        except Exception as e:
            self.fail(e.getMessage())

    @unittest.skip("This test is not implemented yet.")
    def testCloseEditorAndNoSave(self):
        try:
            # Add the s1 data type so that we can undo its add.
            start_transaction("Structure Editor Test Initialization")
            try:
                dt = (Structure) pgm_test_cat.add_data_type(s1, DataTypeConflictHandler.DEFAULT_HANDLER)
            finally:
                end_transaction(commit)

            assert not complex_structure.is_equivalent(model.view_composite)

        except Exception as e:
            self.fail(e.getMessage())

    @unittest.skip("This test is not implemented yet.")
    def testEditWillReEditLastColumnWhenPressingKeyboardEditAction(self):
        try:
            # Add the s1 data type so that we can undo its add.
            start_transaction("Structure Editor Test Initialization")
            try:
                dt = (Structure) pgm_test_cat.add_data_type(s1, DataTypeConflictHandler.DEFAULT_HANDLER)
            finally:
                end_transaction(commit)

            assert not complex_structure.is_equivalent(model.view_composite)

        except Exception as e:
            self.fail(e.getMessage())

    @unittest.skip("This test is not implemented yet.")
    def testChangeHexNumbersOption(self):
        try:
            # Add the s1 data type so that we can undo its add.
            start_transaction("Structure Editor Test Initialization")
            try:
                dt = (Structure) pgm_test_cat.add_data_type(s1, DataTypeConflictHandler.DEFAULT_HANDLER)
            finally:
                end_transaction(commit)

            assert not complex_structure.is_equivalent(model.view_composite)

        except Exception as e:
            self.fail(e.getMessage())

if __name__ == "__main__":
    unittest.main()
