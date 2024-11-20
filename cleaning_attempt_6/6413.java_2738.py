import unittest
from ghidra_scripts import DeleteFunctionDefaultPlatesScript as script_module

class TestDeleteFunctionDefaultPlatesScript(unittest.TestCase):

    def setUp(self):
        self.env = None
        self.tool = None
        self.program = None
        self.script_file = None
        self.builder = None

    def build_program(self):
        builder = ToyProgramBuilder("Test", True, self)
        builder.create_memory(".text", "0x1001000", 0x4000)

        program = builder.get_program()

        # make some functions
        for i in range(6):
            addr = f"0x01001{i:04}8a"
            self.make_function_at(addr)

        return program

    def tearDown(self):
        if self.env is not None:
            self.env.dispose()

    @unittest.skip("This test needs to be implemented")
    def test_delete_plates(self):
        listing = self.program.get_listing()
        function_list = []
        for f in self.program.get_function_manager().get_functions(True):
            comments = f.get_comment_as_array()
            if comments is not None and len(comments) == 1 and comments[0] == " FUNCTION":
                function_list.append(f.get_entry_point())

        script_id = self.env.run_script(self.script_file)
        assert script_id is not None

        self.wait_for_script_completion(script_id, 1200000)

        self.program.flush_events()
        self.wait_for_posted_swing_runnables()

        for addr in function_list:
            f = listing.get_function_at(addr)
            self.assertIsNone(f.get_comment())

    @unittest.skip("This test needs to be implemented")
    def test_delete_plates_on_selection(self):
        set = AddressSet()
        start_addr = get_addr(0x01001978)
        end_addr = get_addr(0x01001ae2)
        set.add_range(start_addr, end_addr)

        tool.fire_plugin_event(
            ProgramSelectionPluginEvent("test", ProgramSelection(set), self.program))

        listing = self.program.get_listing()
        function_list = []
        for f in self.program.get_function_manager().get_functions(set, True):
            comments = f.get_comment_as_array()
            if comments is not None and len(comments) == 1 and comments[0] == " FUNCTION":
                function_list.append(f.get_entry_point())

        script_id = self.env.run_script(self.script_file)
        assert script_id is not None

        self.wait_for_script_completion(script_id, 100000)

        self.program.flush_events()
        self.wait_for_posted_swing_runnables()

        for addr in function_list:
            f = listing.get_function_at(addr)
            self.assertIsNone(f.get_comment())

    def make_function_at(self, addr):
        self.builder.add_bytes_NOP(addr, 0x10)
        self.builder.disassemble(addr, 0x10, True)
        self.builder.create_function(addr)

if __name__ == "__main__":
    unittest.main()
