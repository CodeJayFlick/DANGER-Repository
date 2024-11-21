Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra.app.cmd.function import CreateThunkFunctionCmd
from ghidra.program.database import ProgramDB
from ghidra.program.model.address import AddressSetView
from ghidra.util.task import TaskMonitorAdapter, DummyMonitor

class ThunkFunctionMergeTest(unittest.TestCase):
    def setUp(self):
        self.mtf = MergeTestFacilitator()
        self.latest_program = None
        self.my_program = None

    def test_same_thunk_so_no_change(self):
        mtf.initialize("NotepadMergeListingTest", ProgramModifierListener())
        latest_program = mtf.get_latest_program()
        my_program = mtf.get_private_program()

        as_view = latest_program.memory
        program_merge_manager = ProgramMergeManager(latest_program, my_program, as_view, DummyMonitor())

        diff_as = AddressSetView([latest_program.getAddress(0x1019b), latest_program.getAddress(0x10a1)])
        program_merge_manager.set_diff_filter(ProgramDiffFilter.FUNCTION_DIFFS)
        program_merge_manager.set_merge_filter(ProgramMergeFilter(FUNCTIONS, REPLACE))
        self.assertEqual(diff_as, program_merge_manager.get_filtered_differences())

        perform_merge(as_view, program_merge_manager)

        self.assertEqual(AddressSetView(), program_merge_manager.get_filtered_differences())

    def test_different_thunk_to_address(self):
        mtf.initialize("NotepadMergeListingTest", ProgramModifierListener())
        latest_program = mtf.get_latest_program()
        my_program = mtf.get_private_program()

        as_view = latest_program.memory
        program_merge_manager = ProgramMergeManager(latest_program, my_program, as_view, DummyMonitor())

        diff_as = AddressSetView([latest_program.getAddress(0x1019b), latest_program.getAddress(0x10a1)])
        program_merge_manager.set_diff_filter(ProgramDiffFilter.FUNCTION_DIFFS)
        program_merge_manager.set_merge_filter(ProgramMergeFilter(FUNCTIONS, REPLACE))
        self.assertEqual(diff_as, program_merge_manager.get_filtered_differences())

        perform_merge(as_view, program_merge_manager)

    def test_remove_thunk(self):
        mtf.initialize("NotepadMergeListingTest", ProgramModifierListener())
        latest_program = mtf.get_latest_program()
        my_program = mtf.get_private_program()

        as_view = latest_program.memory
        program_merge_manager = ProgramMergeManager(latest_program, my_program, as_view, DummyMonitor())

        diff_as = AddressSetView([latest_program.getAddress(0x1019b), latest_program.getAddress(0x10a1)])
        program_merge_manager.set_diff_filter(ProgramDiffFilter.FUNCTION_DIFFS)
        program_merge_manager.set_merge_filter(ProgramMergeFilter(FUNCTIONS, REPLACE))
        self.assertEqual(diff_as, program_merge_manager.get_filtered_differences())

    def test_add_thunk(self):
        mtf.initialize("NotepadMergeListingTest", ProgramModifierListener())
        latest_program = mtf.get_latest_program()
        my_program = mtf.get_private_program()

        as_view = latest_program.memory
        program_merge_manager = ProgramMergeManager(latest_program, my_program, as_view, DummyMonitor())

        diff_as = AddressSetView([latest_program.getAddress(0x1019b), latest_program.getAddress(0x10a1)])
        program_merge_manager.set_diff_filter(ProgramDiffFilter.FUNCTION_DIFFS)
        program_merge_manager.set_merge_filter(ProgramMergeFilter(FUNCTIONS, REPLACE))
        self.assertEqual(diff_as, program_merge_manager.get_filtered_differences())

    def test_change_thunk_body(self):
        mtf.initialize("NotepadMergeListingTest", ProgramModifierListener())
        latest_program = mtf.get_latest_program()
        my_program = mtf.get_private_program()

        as_view = latest_program.memory
        program_merge_manager = ProgramMergeManager(latest_program, my_program, as_view, DummyMonitor())

        diff_as = AddressSetView([latest_program.getAddress(0x1019b), latest_program.getAddress(0x10a1)])
        program_merge_manager.set_diff_filter(ProgramDiffFilter.FUNCTION_DIFFS)
        program_merge_manager.set_merge_filter(ProgramMergeFilter(FUNCTIONS, REPLACE))
        self.assertEqual(diff_as, program_merge_manager.get_filtered_differences())

    def test_add_thunks_with_body_overlap(self):
        mtf.initialize("NotepadMergeListingTest", ProgramModifierListener())
        latest_program = mtf.get_latest_program()
        my_program = mtf.get_private_program()

        as_view = latest_program.memory
        program_merge_manager = ProgramMergeManager(latest_program, my_program, as_view, DummyMonitor())

        diff_as = AddressSetView([latest_program.getAddress(0x101984), latest_program.getAddress(0x10a1)])
        program_merge_manager.set_diff_filter(ProgramDiffFilter.FUNCTION_DIFFS)
        program_merge_manager.set_merge_filter(ProgramMergeFilter(FUNCTIONS, REPLACE))
        self.assertEqual(diff_as, program_merge_manager.get_filtered_differences())

    def test_add_thunks_with_body_conflict(self):
        mtf.initialize("NotepadMergeListingTest", ProgramModifierListener())
        latest_program = mtf.get_latest_program()
        my_program = mtf.get_private_program()

        as_view = latest_program.memory
        program_merge_manager = ProgramMergeManager(latest_program, my_program, as_view, DummyMonitor())

        diff_as = AddressSetView([latest_program.getAddress(0x1019b), latest_program.getAddress(0x10a1)])
        program_merge_manager.set_diff_filter(ProgramDiffFilter.FUNCTION_DIFFS)
        program_merge_manager.set_merge_filter(ProgramMergeFilter(FUNCTIONS, REPLACE))
        self.assertEqual(diff_as, program_merge_manager.get_filtered_differences())

    def perform_merge(self, as_view, program_merge_manager):
        success = False
        latest_id = self.latest_program.start_transaction("Merge To Latest")
        try:
            program_merge_manager.merge(as_view, DummyMonitor())
            success = True
        except Exception as e:
            raise e

    # Helper methods.
    def addr(self, program, address):
        return program.getAddress(address)

if __name__ == "__main__":
    unittest.main()
```

Note that Python does not support static method.