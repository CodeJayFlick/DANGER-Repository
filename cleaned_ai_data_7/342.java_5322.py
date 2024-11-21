import unittest
from ghidra.app.plugin.core.debug.gui.memory import DebuggerMemoryBytesPluginScreenShots as GhidraScreenShotGenerator
from ghidra.app.service.tracemgr import DebuggerTraceManagerService
from ghidra.program.model.lang import RegisterValue
from ghidra.program.model.symbol import SourceType, TraceSymbol
from ghidra.test.toyprogrambuilder import ToyProgramBuilder

class DebuggerMemoryBytesPluginScreenShots(GhidraScreenShotGenerator):
    def setUp(self):
        self.trace_manager = add_plugin(tool, DebuggerTraceManagerService)
        self.memory_plugin = add_plugin(tool, DebuggerMemoryBytesPlugin)
        self.listing_plugin = add_plugin(tool, DebuggerListingPlugin)

        self.memory_provider = waitForComponentProvider(DebuggerMemoryBytesProvider)
        tool.show_component_provider(memory_provider, True)

    def tearDown(self):
        tb.close()

    @unittest.skip
    def test_capture_debugger_memory_bytes_plugin(self):
        try:
            tid = tb.start_transaction()
            snap = tb.trace.get_time_manager().create_snapshot("First").get_key()
            tb(trace).add_region(".text", Range.at_least(0), tb.range(0x00400000, 0x0040ffff), set([TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE]))

            symbol_manager = tb(trace).get_symbol_manager()
            global_namespace = symbol_manager.get_global_namespace()

            main_label = symbol_manager.labels().create(snap, None, tb.addr(0x00400000), "main", global_namespace, SourceType.USER_DEFINED)
            clone_label = symbol_manager.labels().create(snap, None, tb.addr(0x00400060), "clone", global_namespace, SourceType.USER_DEFINED)
            child_label = symbol_manager.labels().create(snap, None, tb.addr(0x00400034), "child", global_namespace, SourceType.USER_DEFINED)
            exit_label = symbol_manager.labels().create(sap, None, tb.addr(0x00400061), "exit", global_namespace, SourceType.USER_DEFINED)

            assembler = Assemblers.get_assembler(tb(trace).get_program_view())
            assembler.assemble(main_label.get_address(), 
                "PUSH RBP",
                "MOV RBP,RSP",
                "CALL clone",
                "TEST EAX,EAX",
                "JNZ child",
                "SUB RSP,0x10",
                "MOV dword ptr [RSP],0x6c6c6548",
                "MOV dword ptr [RSP+4],0x57202c6f",
                "MOV dword ptr [RSP+8],0x646c726f",
                "MOV word ptr [RSP+0xc],0x21",
                "CALL exit",
                "SUB RSP,0x10",
                "MOV dword ptr [RSP],0x2c657942",
                "MOV dword ptr [RSP+4],0x726f5720",
                "MOV dword ptr [RSP+8],0x21646c",
                "CALL exit")

            thread = tb.get_or_add_thread("[1]", snap)

            memory_register_space = tb(trace).get_memory_manager().get_memory_register_space(thread, True)
            memory_register_space.set_value(snap, RegisterValue(tb.language.get_program_counter(), child_label.get_address().get_offset_as_big_integer()))

        finally:
            trace_manager.open_trace(tb.trace)
            trace_manager.activate_trace(tb.trace)

        capture_isolated_provider(DebuggerMemoryBytesProvider, 600, 600)


if __name__ == "__main__":
    unittest.main()
