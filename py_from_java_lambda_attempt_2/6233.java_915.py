Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra_app.merge.listing import *

class RefMergerStackTest(unittest.TestCase):

    def testStackRefRemoveNoConflict(self):
        mtf.initialize("NotepadMergeListingTest_X86", ProgramModifierListener())

        @modifyLatest
        def modify_latest(program):
            tx_id = program.start_transaction("Modify Latest Program")
            commit = False
            try:
                ref_mgr = program.get_reference_manager()
                refs = ref_mgr.get_references_from(addr(program, "0x1001af5"), 0)
                self.assertEqual(1, len(refs))
                ref_mgr.delete(refs[0])
                refs = ref_mgr.get_references_from(addr(program, "0x1001b03"), 1)
                self.assertEqual(1, len(refs))
                ref_mgr.delete(refs[0])
                commit = True
            finally:
                program.end_transaction(tx_id, commit)

        @modifyPrivate
        def modify_private(program):
            tx_id = program.start_transaction("Modify My Program")
            commit = False
            try:
                ref_mgr = program.get_reference_manager()
                refs = ref_mgr.get_references_from(addr(program, "0x1001af5"), 0)
                self.assertEqual(1, len(refs))
                ref_mgr.delete(refs[0])
                refs = ref_mgr.get_references_from(addr(program, "0x1002125"), 0)
                self.assertEqual(1, len(refs))
                ref_mgr.delete(refs[0])
                commit = True
            finally:
                program.end_transaction(tx_id, commit)

        execute_merge(ASK_USER)
        wait_for_merge_completion()

        ref_mgr = result_program.get_reference_manager()
        refs = ref_mgr.get_references_from(addr("0x1001af5"), 0)
        self.assertEqual(0, len(refs))

    def testStackRefRemoveVsChangePickLatest(self):
        mtf.initialize("NotepadMergeListingTest_X86", ProgramModifierListener())

        @modify_latest
        def modify_latest(program):
            tx_id = program.start_transaction("Modify Latest Program")
            commit = False
            try:
                ref_mgr = program.get_reference_manager()
                refs = ref_mgr.get_references_from(addr(program, "0x1001af5"), 0)
                self.assertEqual(1, len(refs))
                ref_mgr.delete(refs[0])
                change_stack_ref_offset(program, "0x1001b03", 1, 100, SourceType.ANALYSIS)
                commit = True
            finally:
                program.end_transaction(tx_id, commit)

        @modify_private
        def modify_private(program):
            tx_id = program.start_transaction("Modify My Program")
            commit = False
            try:
                ref_mgr = program.get_reference_manager()
                change_stack_ref_offset(program, "0x1001af5", 0, 100)
                refs = ref_mgr.get_references_from(addr(program, "0x1001b03"), 1)
                self.assertEqual(1, len(refs))
                ref_mgr.delete(refs[0])
                commit = True
            finally:
                program.end_transaction(tx_id, commit)

        execute_merge(ASK_USER)
        choose_radio_button(LATEST_BUTTON)
        choose_radio_button(LATEST_BUTTON)
        wait_for_merge_completion()

        ref_mgr = result_program.get_reference_manager()
        refs = ref_mgr.get_references_from(addr("0x1001af5"), 0)
        self.assertEqual(1, len(refs))
        self.assertTrue(refs[0] instanceof StackReference)

    def testStackRefRemoveVsChangePickMy(self):
        mtf.initialize("NotepadMergeListingTest_X86", ProgramModifierListener())

        @modify_latest
        def modify_latest(program):
            tx_id = program.start_transaction("Modify Latest Program")
            commit = False
            try:
                ref_mgr = program.get_reference_manager()
                refs = ref_mgr.get_references_from(addr(program, "0x1001af5"), 0)
                self.assertEqual(1, len(refs))
                change_stack_ref_offset(program, "0x1001b03", 1, 100, SourceType.ANALYSIS)
                commit = True
            finally:
                program.end_transaction(tx_id, commit)

        @modify_private
        def modify_private(program):
            tx_id = program.start_transaction("Modify My Program")
            commit = False
            try:
                ref_mgr = program.get_reference_manager()
                change_stack_ref_offset(program, "0x1001af5", 0, 100)
                refs = ref_mgr.get_references_from(addr(program, "0x1001b03"), 1)
                self.assertEqual(1, len(refs))
                self.assertTrue(refs[0] instanceof StackReference)
            finally:
                program.end_transaction(tx_id, commit)

        execute_merge(ASK_USER)
        choose_radio_button(MY_BUTTON)
        choose_radio_button(MY_BUTTON)
        wait_for_merge_completion()

        ref_mgr = result_program.get_reference_manager()
        refs = ref_mgr.get_references_from(addr("0x1001af5"), 0)
        self.assertEqual(1, len(refs))
        self.assertTrue(refs[0] instanceof StackReference)

    def testStackRefAddSameNoConflict(self):
        mtf.initialize("NotepadMergeListingTest", ProgramModifierListener())

        @modify_latest
        def modify_latest(program):
            tx_id = program.start_transaction("Modify Latest Program")
            commit = False
            try:
                ref_mgr = program.get_reference_manager()
                ref_mgr.add_stack_reference(addr(program, "0x10024ea"), 1, 0x10, RefType.DATA, SourceType.USER_DEFINED)
                ref_mgr.add_stack_reference(addr(program, "0x1002510"), 0, 0x8, RefType.DATA, SourceType.USER_DEFINED)
                commit = True
            finally:
                program.end_transaction(tx_id, commit)

        @modify_private
        def modify_private(program):
            tx_id = program.start_transaction("Modify My Program")
            commit = False
            try:
                ref_mgr = program.get_reference_manager()
                ref_mgr.add_stack_reference(addr(program, "0x10024ea"), 1, 0x10, RefType.DATA, SourceType.USER_DEFINED)
                ref_mgr.add_stack_reference(addr(program, "0x1002510"), 0, 0x8, RefType.DATA, SourceType.USER_DEFINED)
                commit = True
            finally:
                program.end_transaction(tx_id, commit)

        execute_merge(ASK_USER)
        wait_for_merge_completion()

    def testStackRefAddDiffPickLatest(self):
        mtf.initialize("NotepadMergeListingTest", ProgramModifierListener())

        @modify_latest
        def modify_latest(program):
            tx_id = program.start_transaction("Modify Latest Program")
            commit = False
            try:
                ref_mgr = program.get_reference_manager()
                refs = ref_mgr.get_references_from(addr(program, "0x10024ea"), 1)
                self.assertEqual(1, len(refs) = 1

        @modify_latest
        def modify_latest(program):
            tx_id = program.start_transaction("Modify Latest Program")
            commit = False
            try:
                ref_mgr = program.get_reference_manager()
                refs = ref_mgr.get_references_from(addr(program, "0x10024ea"), 1)
                self.assertEqual(1, len(refs) = 1

        @modify_latest
        def modify_latest(program):
            tx_id = program.start_transaction("Modify Latest Program")
            commit = False
            try:
                refs = ref_mgr.get_references_from(addr(program, "0x10024ea"), 1