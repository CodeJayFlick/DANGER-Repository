import unittest
from ghidra.app.plugin.core.debug.gui.register import DebuggerRegistersPluginScreenShots as GhidraScreenShotGenerator
from org.junit import Before, After, Test


class DebuggerRegistersPluginScreenShots(GhidraScreenShotGenerator):

    def setUp(self):
        self.trace_manager = add_plugin(tool, DebuggerTraceManagerServicePlugin)
        self.registers_plugin = add_plugin(tool, DebuggerRegistersPlugin)

        self.registers_provider = wait_for_component_provider(DebuggerRegistersProvider)
        self.tb = ToyDBTraceBuilder("echo", _X64)


    @Before
    def setUpMine(self):
        pass


    @After
    def tearDownMine(self):
        tb.close()


    @Test
    def test_capture_debugger_registers_plugin(self):

        try:
            tid = tb.start_transaction()
            snap0 = tb.trace.get_time_manager().create_snapshot("First").get_key()
            snap1 = tb.trace.get_time_manager().create_snapshot("Second").get_key()

            thread = tb.get_or_add_thread("[1]", snap0)
            regs = tb(trace).get_memory_manager().get_memory_register_space(thread, True)

            lang = tb(trace).get_base_language()
            regs.set_value(snap0,
                          RegisterValue(lang.get_register("RIP"), BigInteger.valueOf(0x00401234)))
            regs.set_value(snap0,
                          RegisterValue(lang.get_register("RSP"), BigInteger.valueOf(0x7f104321)))
            regs.set_value(snap0,
                          RegisterValue(lang.get_register("RAX"), BigInteger.valueOf(0x00000000)))
            regs.set_value(snap0,
                          RegisterValue(lang.get_register("RBX"), BigInteger.valueOf(0x0)))
            regs.set_value(snap0,
                          RegisterValue(lang.get_register("RCX"), BigInteger.valueOf(5)))
            regs.set_value(snap0,
                          RegisterValue(lang.get_register("RDX"), BigInteger.valueOf(0x80)))

            regs.set_value(snap1,
                          RegisterValue(lang.get_register("RIP"), BigInteger.valueOf(0x00401234)))
            regs.set_value(snap1,
                          RegisterValue(lang.get_register("RSP"), BigInteger.valueOf(0x7f104321)))
            regs.set_value(snap1,
                          RegisterValue(lang.get_register("RAX"), BigInteger.valueOf(0x00000000)))
            regs.set_value(snap1,
                          RegisterValue(lang.get_register("RBX"), BigInteger.valueOf(0x7f104210)))
            regs.set_value(snap1,
                          RegisterValue(lang.get_register("RCX"), BigInteger.valueOf(5)))
            regs.set_value(snap1,
                          RegisterValue(lang.get_register("RDX"), BigInteger.valueOf(0x80)))

            tb(trace).get_code_manager().get_code_register_space(thread, True).defined_data().create(Range.at_least(snap0), lang.get_register("RIP"),
                                                                                                        PointerDataType.data_type)

            trace_manager.open_trace(tb.trace)
            trace_manager.activate_thread(thread)
            trace_manager.activate_snap(1)

            capture_isolated_provider(registers_provider, 600, 600)


    @Test
    def test_capture_debugger_available_registers_dialog(self):

        try:
            tid = tb.start_transaction()
            snap0 = tb(trace).get_time_manager().create_snapshot("First").get_key()

            thread = tb.get_or_add_thread("[1]", snap0)

            trace_manager.open_trace(tb.trace)
            trace_manager.activate_thread(thread)

            perform_action(registers_provider.action_select_registers, False)
            capture_dialog(DebuggerAvailableRegistersDialog)


if __name__ == '__main__':
    unittest.main()
