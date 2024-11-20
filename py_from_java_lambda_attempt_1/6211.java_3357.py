Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra_app_merge_listing import *
from ghidra_program_database import ProgramDB
from ghidra_program_disassemble import Disassembler
from ghidra_program_model_address import AddressSet
from ghidra_program_model_listing import Listing

class DelaySlotCodeUnitMergeManagerTest(unittest.TestCase):

    def setUp(self):
        self.delay_slot_pair1 = bytes([0x54, 0x40, 0x00, 0x01, 0x24, 0x16, 0x00, 0x40])
        self.delay_slot_pair2 = bytes([0x0c, 0x10, 0xcf, 0xe7, 0x02, 0x20, 0x28, 0x21])

    def test_add_latest_delay_slot(self):
        program_modifier_listener = ProgramModifierListener()
        
        def modify_latest(program_db):
            tx_id = program_db.start_transaction("Modify Latest Program")
            try:
                listing = program_db.get_listing()
                listing.clear_code_units(0x80b4, 0x80bb, False)
                program_db.get_memory().set_bytes(0x80b4, self.delay_slot_pair1)
                Disassembler(program_db).disassemble(0x80b4, None)
            finally:
                program_db.end_transaction(tx_id)

        def modify_private(program_db):
            tx_id = program_db.start_transaction("Modify Checked-out Program")
            try:
                listing = program_db.get_listing()
                listing.clear_code_units(0x80b0, 0x80bf, False)
                program_db.get_memory().set_bytes(0x80b0, self.delay_slot_pair2)
                program_db.get_memory().set_bytes(0x80b8, self.delay_slot_pair2)
                Disassembler(program_db).disassemble(0x80b0, None)
            finally:
                program_db.end_transaction(tx_id)

        mtf.initialize("r4000", program_modifier_listener)
        
        execute_merge(ASK_USER)
        choose_code_unit("0x80b0", "0x80bf", KEEP_LATEST)
        wait_for_merge_completion()
        
        self.assert_same_code_units(result_program, latest_program, AddressSet([0x80a0, 0x80cb]))

    def test_add_latest_delay_slot2(self):
        program_modifier_listener = ProgramModifierListener()

        def modify_latest(program_db):
            tx_id = program_db.start_transaction("Modify Latest Program")
            try:
                listing = program_db.get_listing()
                listing.clear_code_units(0x80b4, 0x80bb, False)
                program_db.get_memory().set_bytes(0x80b4, self.delay_slot_pair1)
                Disassembler(program_db).disassemble(0x80b4, None)
            finally:
                program_db.end_transaction(tx_id)

        def modify_private(program_db):
            tx_id = program_db.start_transaction("Modify Checked-out Program")
            try:
                listing = program_db.get_listing()
                listing.clear_code_units(0x80b0, 0x80bf, False)
                program_db.get_memory().set_bytes(0x80b0, self.delay_slot_pair2)
                program_db.get_memory().set_bytes(0x80b8, self.delay_slot_pair2)
                Disassembler(program_db).disassemble(0x80b0, None)
            finally:
                program_db.end_transaction(tx_id)

        mtf.initialize("r4000", program_modifier_listener)
        
        execute_merge(ASK_USER)
        choose_code_unit("0x80b0", "0x80bf", KEEP_ORIGINAL)
        wait_for_merge_completion()
        
        self.assert_same_code_units(result_program, original_program, AddressSet([0x80a0, 0x80cb]))

    def test_add_latest_delay_slot3(self):
        program_modifier_listener = ProgramModifierListener()

        def modify_latest(program_db):
            tx_id = program_db.start_transaction("Modify Latest Program")
            try:
                listing = program_db.get_listing()
                listing.clear_code_units(0x80b4, 0x80bb, False)
                program_db.get_memory().set_bytes(0x80b4, self.delay_slot_pair1)
                Disassembler(program_db).disassemble(0x80b4, None)
            finally:
                program_db.end_transaction(tx_id)

        def modify_private(program_db):
            tx_id = program_db.start_transaction("Modify Checked-out Program")
            try:
                listing = program_db.get_listing()
                listing.clear_code_units(0x80b0, 0x80bf, False)
                program_db.get_memory().set_bytes(0x80b0, self.delay_slot_pair2)
                program_db.get_memory().set_bytes(0x80b8, self.delay_slot_pair2)
                Disassembler(program_db).disassemble(0x80b0, None)
            finally:
                program_db.end_transaction(tx_id)

        mtf.initialize("r4000", program_modifier_listener)
        
        execute_merge(ASK_USER)
        choose_code_unit("0x80b0", "0x80bf", KEEP_MY)
        wait_for_merge_completion()
        
        self.assert_same_code_units(result_program, my_program, AddressSet([0x80a0, 0x80cb]))

if __name__ == '__main__':
    unittest.main()
```

Please note that this is a direct translation of the Java code into Python. It might not be perfect and may require some adjustments to work correctly in your specific environment.