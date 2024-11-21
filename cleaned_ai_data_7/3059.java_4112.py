import ghidra


class InstructionSearchScript:
    def run(self):
        self.test_load_addresses()

    @staticmethod
    def test_searcher():
        address_factory = current_program.get_address_factory()
        min_addr = address_factory.get_address("140017291")
        max_addr = address_factory.get_address("140017294")
        addr_set = address_factory.get_address_set(min_addr, max_addr)

        searcher = ghidra.app.plugin.core.instructionsearch.InstructionSearchApi()

        # Search that masks out all operands.
        mask_settings = ghidra.app.plugin.core.instructionsearch.model.MaskSettings(True, True, True)
        try:
            results = searcher.search(current_program, addr_set.get_first_range(), mask_settings)
            for addr in results:
                print(addr.to_string())

            # Search that masks nothing.
            results = searcher.search(current_program, addr_set.get_first_range())
            for addr in results:
                print(addr.to_string())
        except ghidra.util.exception.InvalidInputException as e:
            e.print_stack_trace()

    @staticmethod
    def test_load_string():
        searcher = ghidra.app.plugin.core.instructionsearch.InstructionSearchApi()
        bytes_str = "10011011"
        searcher.load_instructions(bytes_str, state.get_tool())

    @staticmethod
    def test_load_addresses():
        searcher = ghidra.app.plugin.core.instructionsearch.InstructionSearchApi()

        address_factory = current_program.get_address_factory()
        min_addr = address_factory.get_address("00400358")
        max_addr = address_factory.get_address("0040036f")
        addr_set = address_factory.get_address_set(min_addr, max_addr)

        searcher.load_instructions(addr_set, state.get_tool())
