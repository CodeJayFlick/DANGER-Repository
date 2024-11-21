import unittest
from ghidra_framework import *
from ghidra_program_database import *

class RegisterFieldFactoryTest(unittest.TestCase):

    def setUp(self):
        self.program = build_program()
        self.env = TestEnv()
        tool = self.env.show_tool(self.program)
        tool.add_plugin(CodeBrowserPlugin())
        tool.add_plugin(NextPrevAddressPlugin())
        self.cb = self.env.get_plugin(CodeBrowserPlugin())

    def tearDown(self):
        self.env.dispose()

    def test_register_field(self):

        function_iterator = self.program.function_manager.get_functions(
            self.program.min_address, True)
        function = next(function_iterator)
        entry = function.entry_point
        end = function.body.max_address

        program_context = self.program.context
        non_context_regs = get_non_context_leaf_registers(program_context)

        transaction_id = self.program.start_transaction("test")
        try:
            for register in non_context_regs:
                if register.parent_register is None:
                    flag_reg_count += 1
                else:
                    sub_reg_count += 1

                program_context.set_value(register, entry, end, BigInteger(5))

        finally:
            self.program.end_transaction(transaction_id, True)
        self.program.flush_events()
        unittest.util.waitForPostedSwingRunnables()
        self.cb.update_now()

        self.assertTrue(self.cb.go_to_field(entry, RegisterFieldFactory.FIELD_NAME, 0, 0, 0))
        listing_text_field = ListingTextField(self.cb.current_field())
        self.assertEqual(flag_reg_count + (sub_reg_count // 2), listing_text_field.num_rows())

    def test_subset_register_field(self):

        function_iterator = self.program.function_manager.get_functions(
            self.program.min_address, True)
        function = next(function_iterator)
        entry = function.entry_point

        program_context = self.program.context
        regs = get_non_context_leaf_registers(program_context)

        count = 0
        transaction_id = self.program.start_transaction("test")
        try:
            for i in range(len(regs)):
                if i % 2 == 0:
                    program_context.set_value(regs[i], entry, entry, BigInteger(i))

            for register in regs:
                value = program_context.get_non_default_value(register, entry)
                parent_register = register.parent_register
                if value is not None and value.signed_value is not None and (parent_register is None or program_context.get_non_default_value(parent_register, entry).has_value()):
                    count += 1

        finally:
            self.program.end_transaction(transaction_id, True)

        self.program.flush_events()
        unittest.util.waitForPostedSwingRunnables()
        self.cb.update_now()

        self.assertTrue(self.cb.go_to_field(entry, RegisterFieldFactory.FIELD_NAME, 0, 0, 0))
        listing_text_field = ListingTextField(self.cb.current_field())
        self.assertEqual(count, listing_text_field.num_rows())

    def test_program_location(self):

        function_iterator = self.program.function_manager.get_functions(
            self.program.min_address, True)
        function = next(function_iterator)
        entry = function.entry_point

        program_context = self.program.context
        transaction_id = self.program.start_transaction("test")
        try:
            program_context.set_value(self.program.register("C"), entry, entry, BigInteger(1))
            program_context.set_value(self.program.register("lrh"), entry, entry, BigInteger(2))
            program_context.set_value(self.program.register("lrl"), entry, entry, BigInteger(3))
            program_context.set_value(self.program.register("r0"), entry, entry, BigInteger(4))
            program_context.set_value(self.program.register("r1l"), entry, entry, BigInteger(5))

        finally:
            self.program.end_transaction(transaction_id, True)

        self.program.flush_events()
        unittest.util.waitForPostedSwingRunnables()
        self.cb.update_now()

        self.assertTrue(self.cb.go_to_field(entry, RegisterFieldFactory.FIELD_NAME, 0, 0, 0))
        self.assertTrue(isinstance(self.cb.current_location(), RegisterFieldLocation))

        register_field_location = RegisterFieldLocation(self.cb.current_location())
        reg_assumes = register_field_location.register_strings
        self.assertEqual(4, len(reg_assumes))
        self.assertEqual("assume C = 0x1", reg_assumes[0])
        self.assertEqual("assume lr = 0x20003", reg_assumes[1])
        self.assertEqual("assume r0 = 0x4", reg_assumes[2])
        self.assertEqual("assume r1l = 0x5", reg_assumes[3])

    def get_non_context_leaf_registers(self, program_context):
        non_context_regs = []
        for register in program_context.registers:
            if register.is_processor_context or register.has_children:
                continue
            non_context_regs.append(register)
        return non_context_regs

if __name__ == "__main__":
    unittest.main()
