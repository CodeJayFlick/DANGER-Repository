Here is the translation of the given Java code into equivalent Python:

```Python
import unittest
from ghidra_plugin import GhidraPluginTest


class MnemonicSearchPluginTest(GhidraPluginTest):
    def setUp(self):
        self.env = TestEnv()
        self.tool = self.env.get_tool()
        self.program = build_program()

        self.search_mnemonic_operands_no_const_action = get_action(
            plugin=self.plugin, action_name="Include Operands (except constants)"
        )
        self.search_mnemonic_no_operands_no_const_action = get_action(
            plugin=self.plugin, action_name="Exclude Operands"
        )
        self.search_mnemonic_operands_const_action = get_action(
            plugin=self.plugin, action_name="Include Operands"

        )

    def build_program(self):
        builder = ProgramBuilder("TestX86", "x86")
        builder.create_memory(".text", 0x1001000, 0x6600)

        # create and disassemble some code
        builder.set_bytes(0x01004062, b"\x55\x8b\xec\x81\xec\x04\x01\x00\x00")
        builder.disassemble(0x01004062, 9, True)
        return builder.get_program()

    def test_search_mnemonic_operands_no_const(self):
        selection = ProgramSelection(addr=0x10040062, end_addr=0x100406a)
        self.tool.fire_plugin_event(event_type="Test", program=self.program)

        perform_action(
            action=self.search_mnemonic_operands_no_const_action,
            provider=self.cb.get_provider(),
            show_dialog=True
        )

    def test_search_mnemonic_no_operands_no_const(self):
        selection = ProgramSelection(addr=0x10040062, end_addr=0x100406a)
        self.tool.fire_plugin_event(event_type="Test", program=self.program)

        perform_action(
            action=self.search_mnemonic_no_operands_no_const_action,
            provider=self.cb.get_provider(),
            show_dialog=True
        )

    def test_search_mnemonic_operands_const(self):
        selection = ProgramSelection(addr=0x10040062, end_addr=0x100406a)
        self.tool.fire_plugin_event(event_type="Test", program=self.program)

        perform_action(
            action=self.search_mnemonic_operands_const_action,
            provider=self.cb.get_provider(),
            show_dialog=True
        )

    def test_multiple_selection(self):
        range1 = AddressRangeImpl(start_addr=0x10040062, end_addr=0x1004064)
        range2 = AddressRangeImpl(start_addr=0x100406c, end_addr=0x100406e)
        addr_set = set()
        addr_set.add(range1)
        addr_set.add(range2)

        make_selection(tool=self.tool, program=self.program, address_set=addr_set)

        perform_action(
            action=self.search_mnemonic_operands_const_action,
            provider=self.cb.get_provider(),
            show_dialog=False
        )

    def addr(self, offset):
        return self.program.min_address.new_address(offset)


if __name__ == "__main__":
    unittest.main()
```

Please note that this is a direct translation of the given Java code into equivalent Python. It might not be perfect and may require some adjustments to work correctly in your specific environment.