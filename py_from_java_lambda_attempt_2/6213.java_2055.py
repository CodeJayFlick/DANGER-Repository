Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra_app_merge_listing import *

class EquateMergeManager2Test(unittest.TestCase):

    def testAddDiffPickLatest(self):
        mtf.initialize("NotepadMergeListingTest", ProgramModifierListener())
        
        modify_latest = lambda program: (
            tx_id = program.start_transaction("Modify Latest Program")
            commit = False
            try:
                equate_tab = program.get_equate_table()
                addr = address(program, "0x1002d18")
                equate_tab.create_equate("TWO", 2).add_reference(addr, 1)
                equate_tab.create_equate("ONE", 1).add_reference(addr, 1)
            except DuplicateNameException | InvalidInputException as e:
                self.fail(e.get_message())
            finally:
                program.end_transaction(tx_id, commit)

        modify_private = lambda program: (
            tx_id = program.start_transaction("Modify My Program")
            commit = False
            try:
                equate_tab = program.get_equate_table()
                addr = address(program, "0x1002d18")
                equate_tab.get_equate("uno").add_reference(addr, 1)
            except DuplicateNameException | InvalidInputException as e:
                self.fail(e.get_message())
            finally:
                program.end_transaction(tx_id, commit)

        execute_merge(ASK_USER)
        choose_equate("0x1002d18", 1, KEEP_MY)
        wait_for_merge_completion()

        equate_tab = result_program.get_equate_table()
        equates = equate_tab.get_equates(address("0x1002d18"), 1)
        self.assertEqual(2, len(equates))
        eq = equates[0]
        self.assertEqual("TWO", eq.name())
        self.assertEqual(2L, eq.value)

    def testAddDiffPickMy(self):
        mtf.initialize("NotepadMergeListingTest", ProgramModifierListener())

        modify_latest = lambda program: (
            tx_id = program.start_transaction("Modify Latest Program")
            commit = False
            try:
                equate_tab = program.get_equate_table()
                addr = address(program, "0x1002533")
                try:
                    equate_tab.create_equate("0x1", 1).add_reference(addr, 1)
                except DuplicateNameException | InvalidInputException as e:
                    self.fail(e.get_message())
            finally:
                program.end_transaction(tx_id, commit)

        modify_private = lambda program: (
            tx_id = program.start_transaction("Modify My Program")
            commit = False
            try:
                equate_tab = program.get_equate_table()
                addr = address(program, "0x1002533")
                equate_tab.get_equate("uno").add_reference(addr, 1)
            except DuplicateNameException | InvalidInputException as e:
                self.fail(e.get_message())
            finally:
                program.end_transaction(tx_id, commit)

        execute_merge(ASK_USER)
        wait_for_prompting()
        choose_equate("0x1002533", 1, KEEP_MY)
        wait_for_merge_completion()

        equate_tab = result_program.get_equate_table()
        equates = equate_tab.get_equates(address("0x1002533"), 1)
        self.assertEqual(1, len(equates))
        eq = equates[0]
        self.assertEqual("uno", eq.name())
        self.assertEqual(1L, eq.value)

    def runTestAddNameDiffPickIndicated(self, addr_str, data_type, byte_data, value):
        mtf.initialize("NotepadMergeListingTest_X86", OriginalProgramModifierListener())

        modify_original = lambda program: (
            tx_id = program.start_transaction("Setup Original Program")
            commit = False
            try:
                listing = program.get_listing()
                start_addr = address(program, addr_str)
                program.get_memory().set_bytes(start_addr, byte_data)
                create_instruction(program, start_addr)
                instruction = listing.get_instruction_at(start_addr)
                self.assertTrue(instruction is not None)
                self.assertEqual(2, len(instruction.operands))
            except MemoryAccessException as e:
                self.fail(e.get_message())
            finally:
                program.end_transaction(tx_id, commit)

        modify_latest = lambda program: (
            tx_id = program.start_transaction("Modify Latest Program")
            commit = False
            try:
                equate_tab = program.get_equate_table()
                addr = address(program, addr_str)
                try:
                    equate_tab.create_equate("FOO", value).add_reference(addr, 1)
                except DuplicateNameException | InvalidInputException as e:
                    self.fail(e.get_message())
            finally:
                program.end_transaction(tx_id, commit)

        modify_private = lambda program: (
            tx_id = program.start_transaction("Modify My Program")
            commit = False
            try:
                equate_tab = program.get_equate_table()
                addr = address(program, addr_str)
                try:
                    equate_tab.create_equate("BAR", value).add_reference(addr, 1)
                except DuplicateNameException | InvalidInputException as e:
                    self.fail(e.get_message())
            finally:
                program.end_transaction(tx_id, commit)

        execute_merge(ASK_USER)
        choose_equate(addr_str, len(byte_data), KEEP_MY)  # -0x20
        wait_for_merge_completion()

        equate_tab = result_program.get_equate_table()
        equates = equate_tab.get_equates(address(addr_str), 1)
        self.assertEqual(1, len(equates))
        eq = equates[0]
        self.assertEqual("BAR", eq.name())
        self.assertEqual(value, eq.value)

    def testAddNameDiffOnQWordDataUpperBit0PickMy(self):
        runTestAddNameDiffPickIndicated("0x1002d24", QWordDataType(), byte_data=bytearray(8), value=value)

    # ... and so on for the rest of the tests

if __name__ == "__main__":
    unittest.main()
```

Please note that this is a direct translation from Java to Python, without considering any specific requirements or best practices in Python.