Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra_program import Program
from ghidra_listing import Listing
from ghidra_memory import Memory
from ghidra_instruction import InstructionPrototype
from ghidra_data_type import DataType, TerminatedStringDataType, StringDataType, DWordDataType, ArrayDataType, CharDataType

class TestDataTypeMarkupItem(unittest.TestCase):

    def setUp(self):
        self.source_program = Program()
        self.destination_program = Program()

    @unittest.skip("Not implemented")
    def test_replace_data_type_where_none(self):
        source_address = "0x010074e6"
        source_data_type = TerminatedStringDataType()
        data = set_data_type(self.source_program, addr(source_address), source_data_type)
        destination_address = "0x010074e6"
        destination_data = self.destination_program.get_listing().get_data_at(addr(destination_address))
        validator = DataTypeValidator(data, destination_data, ReplaceDataChoices.REPLACE_FIRST_DATA_ONLY)
        do_test_find_and_apply_markup_item(validator)

    @unittest.skip("Not implemented")
    def test_matching_data_types(self):
        source_address = "0x010074e6"
        source_data_type = TerminatedStringDataType()
        data = set_data_type(self.source_program, addr(source_address), source_data_type)
        destination_address = "0x010074e6"
        destination_data_type = StringDataType()
        destination_data = self.destination_program.get_listing().get_data_at(addr(destination_address))
        validator = DataTypeValidator(data, destination_data, ReplaceDataChoices.REPLACE_FIRST_DATA_ONLY)
        do_test_find_and_do_nothing_on_apply_of_same_markup_item(validator)

    @unittest.skip("Not implemented")
    def test_replace_small_data_type_with_larger_that_fits(self):
        source_address = "0x010074e6"
        source_data_type = TerminatedStringDataType()
        data = set_data_type(self.source_program, addr(source_address), source_data_type)
        destination_address = "0x010074e6"
        destination_data_type = StringDataType()
        destination_data = self.destination_program.get_listing().get_data_at(addr(destination_address))
        validator = DataTypeValidator(data, destination_data, ReplaceDataChoices.REPLACE_FIRST_DATA_ONLY)
        do_test_find_and_apply_markup_item(validator)

    @unittest.skip("Not implemented")
    def test_replace_larger_with_smaller(self):
        source_address = "0x010074e6"
        source_data_type = StructureDataType("StructA", 0).add(DWordDataType())
        data = set_data_type(self.source_program, addr(source_address), source_data_type)
        destination_address = "0x010074e6"
        destination_data_type = StructureDataType("StructB", 0).add(ArrayDataType(CharDataType(), 12, 1))
        destination_data = self.destination_program.get_listing().get_data_at(addr(destination_address))
        validator = DataTypeValidator(data, destination_data, ReplaceDataChoices.REPLACE_FIRST_DATA_ONLY)
        do_test_find_and_apply_markup_item(validator)

    @unittest.skip("Not implemented")
    def test_replace_with_larger_when_blocked_by_instruction(self):
        source_address = "0x010074e6"
        source_data_type = TerminatedStringDataType()
        data = set_data_type(self.source_program, addr(source_address), source_data_type)
        destination_address = "0x010074e6"
        destination_data = self.destination_program.get_listing().get_data_at(addr(destination_address))
        instruction_address = addr(destination_address).add(4)
        instruction = create_instruction(self.destination_program, instruction_address)
        validator = DataTypeValidator(data, destination_data, ReplaceDataChoices.REPLACE_-FIRST_DATA_ONLY)
        do_test_find_and_apply_markup_item_apply_fails(validator)

    def set_data_type(program, address, data_type):
        tx_id = program.start_transaction("Change Data Type")
        try:
            listing = program.get_listing()
            source_data = listing.get_data_at(address)
            if source_data is None:
                return None
            listing.clear_code_units(address, source_data.max_address(), False)
            data = listing.create_data(address, data_type, 0) if len(data_type) > 0 else listing.create_data(address, data_type)
            commit = True
            return data
        except Exception as e:
            # Commit is false by default so nothing else to do.
            return None
        finally:
            program.end_transaction(tx_id, False)

    def create_instruction(program, address):
        tx_id = program.start_transaction("Create Instruction")
        try:
            listing = program.get_listing()
            memory = program.get_memory()
            buf = DumbMemBufferImpl(memory, address)
            context = ProgramProcessorContext(program.get_program_context(), address)
            proto = program.get_language().parse(buf, context, False)
            instruction = listing.create_instruction(address, proto, buf, context)
            commit = True
            return instruction
        except Exception as e:
            # Commit is false by default so nothing else to do.
            return None
        finally:
            program.end_transaction(tx_id, False)

    def test_replace_data_type_where_none(self):
        source_address = "0x010074e6"
        source_data_type = TerminatedStringDataType()
        data = set_data_type(self.source_program, addr(source_address), source_data_type)
        destination_address = "0x010074e6"
        destination_data = self.destination_program.get_listing().get_data_at(addr(destination_address))
        validator = DataTypeValidator(data, destination_data, ReplaceDataChoices.REPLACE_-FIRST_DATA_ONLY)
        do_test_find_and_apply_markup_item(validator)

    def test_replace_matching_data_types(self):
        source_address = "0x010074e6"
        source_data_type = TerminatedStringDataType()
        data = set_data_type(self.source_program, addr(source_address), source_data_type)
        destination_address = "0x010074e6"
        destination_data_type = StringDataType()
        destination_data = self.destination_program.get_listing().get_data_at(addr(destination_address))
        validator = DataTypeValidator(data, destination_data, ReplaceDataChoices.REPLACE_-FIRST_DATA_ONLY)
        do_test_find_and_do_nothing_on_apply_of_same_markup_item(validator)

    def test_replace_small_data_type_with_larger_that_fits(self):
        source_address = "0x010074e6"
        source_data_type = TerminatedStringDataType()
        data = set_data_type(self.source_program, addr(source_address), source_data_type)
        destination_address = "0x010074e6"
        destination_data_type = StringDataType()
        destination_data = self.destination_program.get_listing().get_data_at(addr(destination_address))
        validator = DataTypeValidator(data, destination_data, ReplaceDataChoices.REPLACE_-FIRST_DATA_ONLY)
        do_test_find_and_apply_markup_item(validator)

    def test_replace_larger_with_smaller(self):
        source_address = "0x010074e6"
        source_data_type = StructureDataType("StructA", 0).add(DWordDataType())
        data = set_data_type(self.source_program, addr(source_address), source_data_type)
        destination_address = "0x010074e6"
        destination_data_type = StructureDataType("StructB", 0).add(ArrayDataType(CharDataType(), 12, 1))
        destination_data = self.destination_program.get_listing().get_data_at(addr(destination_address))
        validator = DataTypeValidator(data, destination_data, ReplaceDataChoices.REPLACE_-FIRST_DATA_ONLY)
        do_test_find_and_apply_markup_item(validator)

    def test_replace_with_larger_when_blocked_by_instruction(self):
        source_address = "0x010074e6"
        source_data_type = TerminatedStringDataType()
        data = set_data_type(self.source_program, addr(source_address), source_data_type)
        destination_address = "0x010074e6"
        destination_data = self.destination_program.get_listing().get_data_at(addr(destination_address))
        instruction_address = addr(destination_address).add(4)
        instruction = create_instruction(self.destination_program, instruction_address)
        validator = DataTypeValidator(data, destination_data, ReplaceDataChoices.REPLACE_-FIRST_DATA_ONLY)
        do_test_find_and_apply_markup_item_apply_fails(validator)

    def test_replace Undefined Only data type where none(self):
        source_address = "0x010074e6"
        source_data_type = TerminatedStringDataType()
        data = set_data_type(self.source_program, addr(source_address), source_data_type)
        destination_address = "0x010074e6"
        destination_data = self.destination_program.get_listing().get_data_at(addr(destination_address))
        validator = DataTypeValidator(data, destination_data, ReplaceDataChoices.REPLACE_UNDEFINED_DATA_ONLY)
        do_test_find_and_apply_markup_item(validator)

    def test_replace Undefined Only matching data types(self):
        source_address = "0x010074e6"
        source_data_type = TerminatedStringDataType()
        data = set_data_type(self.source_program, addr(source_address), source_data_type)
        destination_address = "0x010074e6"
        destination_data_type = StringDataType()
        destination_data = self.destination_program.get_listing().get_data_at(addr(destination_address))
        validator = DataTypeValidator(data, destination_data, ReplaceDataChoices.REPLACE_UNDEFINED_DATA_ONLY)
        do_test_find_and_do_nothing_on_apply_of_same_markup_item(validator)

    def test_replace Undefined Only small data type with larger that fits(self):
        source_address = "0x010074e6"
        source_data_type = TerminatedStringDataType()
        data = set_data_type(self.source_program, addr(source_address), source_data_type)
        destination_address = "0x010074e6"
        destination_data_type = StringDataType()
        destination_data = self.destination_program.get_listing().get_data_at(addr(destination_address))
        validator = DataTypeValidator(data, destination_data, ReplaceDataChoices.REPLACE_UNDEFINED_DATA_ONLY)
        do_test_find_and_apply_markup_item(validator)

    def test_replace Undefined Only larger with smaller(self):
        source_address = "0x010074e6"
        source_data_type = StructureDataType("StructA", 0).add(DWordDataType())
        data = set_data_type(self.source_program, addr(source_address), source_data_type)
        destination_address = "0x010074e6"
        destination_data_type = StructureDataType("StructB", 0).add(ArrayDataType(CharDataType(), 12, 1))
        destination_data = self.destination_program.get_listing().get_data_at(addr(destination_address))
        validator = DataTypeValidator(data, destination_data, ReplaceDataChoices.REPLACE_UNDEFINED_DATA_ONLY)
        do_test_find_and_apply_markup_item(validator)

    def test_replace Undefined Only with larger when blocked by data(self):
        source_address = "0x010074e6"
        source_data_type = TerminatedStringDataType()
        data = set_data_type(self.source_program, addr(source_address), source_data_type)
        destination_address = "0x010074e6"
        destination_data = self.destination_program.get_listing().get_data_at(addr(destination_address))
        instruction_address = addr(destination_address).add(4)
        instruction = create_instruction(self.destination_program, instruction_address)
        validator = DataTypeValidator(data, destination_data, ReplaceDataChoices.REPLACE_UNDEFINED_DATA_ONLY)
        do_test_find_and_apply_markup_item_apply_fails(validator)

    def test_replace Undefined Only with larger when blocked by data at end(self):
        source_address = "0x010074e6"
        source_data_type = TerminatedStringDataType()
        data = set_data_type(self.source_program, addr(source_address), source_data_type)
        destination_address = "0x010074e6"
        destination_data = self.destination_program.get_listing().get_data_at(addr(destination_address))
        instruction_address = addr(destination_address).add(11)
        instruction = create_instruction(self.destination_program, instruction_address)
        validator = DataTypeValidator(data, destination_data, ReplaceDataChoices.REPLACE_UNDEFINED_DATA_ONLY)
        do_test_find_and_apply_markup_item(validator)

    def test_replace Undefined Only with larger when blocked by data at end and instruction(self):
        source_address = "0x010074e6"
        source_data_type = TerminatedStringDataType()
        data = set_data_type(self.source_program, addr(source_address), source_data_type)
        destination_address = "0x010074e6"
        destination_data = self.destination_program.get_listing().get_data_at(addr(destination_address))
        instruction_address = addr(destination_address).add(11)
        instruction = create_instruction(self.destination_program, instruction_address)
        validator = DataTypeValidator(data, destination_data, ReplaceDataChoices.REPLACE_UNDEFINED_DATA_ONLY)
        do_test_find_and_apply_markup_item_1(validator)

    def test_replace Undefined Only with larger when blocked by data at end and two instructions(self):
        source_address = "0x010074e6"
        source_data_type = TerminatedStringDataType()
        data = set_data_type(self.source_program, addr(source_address), source_data_type)
        destination_address = "0x010074e6"
        destination_data = self.destination_program.get_listing().get_data_at(addr(destination_address))
        instruction_address1 = addr(destination_address).add(4)
        instruction1 = create_instruction(self.destination_program, instruction_address1)
        instruction_address2 = addr(destination_address).add(11)
        instruction2 = create_instruction(self.destination_program, instruction_address2)
        validator = DataTypeValidator(data, destination_data, ReplaceDataChoices.REPLACE_UNDEFINED_DATA_ONLY)
        do_test_find_and_apply_markup_item_0(validator)

    def test_replace Undefined Only with larger when blocked by data at end and three instructions(self):
        source_address = "0x010074e6"
        source_data_type = TerminatedStringDataType()
        data = set_data_type(self.source_program, addr(source_address), source_data_type)
        destination_address = "0x010074e6"
        destination_data = self.destination_program.get_listing().get_data_at(addr(destination_address))
        instruction_address1 = addr(destination_address).add(4)
        instruction1 = create_instruction(self.destination_program, instruction_address1)
        instruction_address2 = addr(destination_address).add(11)
        instruction2 = create_instruction(self.destination_program, instruction_address2)
        validator = DataTypeValidator(data, destination_data, ReplaceDataChoices.REPLACE_UNDEFINED_DATA_ONLY)
        do_test_find_and_apply_markup_item_0(validator)

    def test_replace Undefined Only with larger when blocked by data at end and four instructions(self):
        source_address = "