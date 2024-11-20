import unittest
from ghidra_program_database import ProgramDB
from ghidra_address_space import AddressSpace
from ghidra_function_manager import FunctionManager


class StackFrameTest(unittest.TestCase):

    def setUp(self):
        self.program = create_default_program("test", "toy")
        self.space = self.program.get_address_factory().get_default_address_space()
        self.function_manager = self.program.get_function_manager()
        transaction_id = self.program.start_transaction("Test")

    def tearDown(self):
        if self.program is not None:
            self.program.end_transaction(transaction_id, True)
            self.program.release(self)

    def create_function(self, name: str, entry_point: int, body: list[int]) -> tuple[Function, Address]:
        function_manager = self.function_manager
        function_manager.create_function(name, entry_point, body, SourceType.USER_DEFINED)
        f = function_manager.get_function_at(entry_point)
        return f

    def test_create_variable_negative_stack(self):
        do_create_variable_test(-4)

    def test_create_variable_positive_stack(self):
        do_create_variable_test(4)

    def do_create_variable_test(self, base_param_offset: int) -> None:
        frame = self.create_function("foo", 100, [100, 200]).get_stack_frame()
        frame.set_custom_variable_storage(True)
        dt = ByteDataType()

        names = ["local_test" + str(i) for i in range(16)]
        vars = []
        for offset in range(-8, 8):
            if base_param_offset < abs(offset):
                var_name = "myParam_" + str(abs(offset))
            else:
                var_name = "local_test" + str(offset)
            var = frame.create_variable(var_name, offset, dt, SourceType.USER_DEFINED)
            var.set_comment("My Comment" + str(i))

        function_manager.invalidate_cache(False)

    def test_set_local_size(self):
        # TODO
        pass

if __name__ == "__main__":
    unittest.main()
