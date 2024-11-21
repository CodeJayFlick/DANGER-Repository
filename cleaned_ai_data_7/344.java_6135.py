import unittest
from ghidra_framework import *
from ghidra_program_manager import ProgramManager
from ghidra_trace_manager_service import DebuggerTraceManagerService
from ghidra_memview_plugin import MemviewProvider, DebuggerMemviewPlugin

class TestDebuggerMemviewPlugin(unittest.TestCase):

    def setUp(self):
        self.program_manager = add_plugin(tool, ProgramManager())
        self.trace_manager = add_plugin(tool, DebuggerTraceManagerService())
        self.memview_plugin = add_plugin(tool, DebuggerMemviewPlugin())

        self.memview_provider = wait_for_component_provider(MemviewProvider)
        
        self.tb = ToyDBTraceBuilder("echo", _X64)

    def tearDown(self):
        if hasattr(self, 'prog_echo'):
            self.prog_echo.release()
        if hasattr(self, 'prog_libc'):
            self.prog_libc.release()

    @unittest.skipIf(not ghidra, "Ghidra not installed")
    def test_capture_debugger_memview_plugin(self):

        populate_trace_and_programs()

        memview_provider.set_visible(True)
        capture_isolated_provider(memview_provider, 1000, 400)

    def populate_trace_and_programs():
        root = tool.get_project().get_project_data().get_root_folder()
        
        try:
            with tb.start_transaction() as tid:
                thread1 = tb.trace.thread_manager.add_thread("[0]", Range.open_closed(0L, 40L))
                tb(trace).thread_manager.add_thread("[1]", Range.open_closed(3L, 50L))
                tb(trace).thread_manager.add_thread("[2]", Range.open_closed(5L, 20L))

        try:
            with tb.start_transaction() as tid:
                tb(trace).module_manager.add_loaded_module("/bin/bash", "/bin/bash", tb.range(0x00400000, 0x0060ffff), 0)
                tb(trace).module_manager.add_loaded_module("/lib/libc.so.6", "/lib/libc.so.6", tb.range(0x7fac0000, 0x7faeffff), 10)

        try:
            with tb.start_transaction() as tid:
                tb(trace).memory_manager.add_region("bash.text", Range.at_least(5L), tb.range(0x00400000, 0x0040ffff), TraceMemoryFlag.EXECUTE)
                tb(trace).memory_manager.add_region("bash.data", Range.at_least(6L), tb.range(0x00500000, 0x0060ffff), TraceMemoryFlag.READ | TraceMemoryFlag.WRITE)

                tb(trace).memory_manager.add_region("libc.text", Range.at_least(15L), tb.range(0x7fac0000, 0x7facffff), TraceMemoryFlag.EXECUTE)
                tb(trace).memory_manager.add_region("libc.data", Range.at_least(16L), tb.range(0x7fae0000, 0x7faeffff), TraceMemoryFlag.READ | TraceMemoryFlag.WRITE)

        try:
            with tb.start_transaction() as tid:
                threads = set()
                kinds = set()
                threads.add(thread1)
                kinds.add(TraceBreakpointKind.HW_EXECUTE)
                tb(trace).breakpoint_manager.add_breakpoint("bpt1", Range.closed(17L, 25L), tb.range(0x7fac1234, 0x7fc1238), threads, kinds, True, "break here")

        # prog_echo = create_default_program("bash", ProgramBuilder._X64, self)
        # prog_libc = create_default_program("libc.so.6", ProgramBuilder._X64, self)

        root.create_file("trace", tb.trace, TaskMonitor.DUMMY)
        root.create_file("echo", prog_echo, TaskMonitor.DUMMY)
        root.create_file("libc.so.6", prog_libc, TaskMonitor.DUMMY)

        trace_manager.open_trace(tb(trace))
        trace_manager.activate_trace(tb(trace))

    # program_manager.open_program(prog_echo)
    # program_manager.open_program(prog_libc)

if __name__ == "__main__":
    unittest.main()
