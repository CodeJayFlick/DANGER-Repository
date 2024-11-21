import unittest
from ghidra.app.plugin.core.debug.service.tracemgr import DebuggerTraceManagerService
from ghidra.app.plugin.core.progmgr import ProgramManagerPlugin
from ghidra.framework.model.domain_folder import DomainFolder
from ghidra.program.database import ProgramBuilder, ToyProgramBuilder
from ghidra.program.model.address import Address
from ghidra.program.model.listing import Program
from ghidra.test.toy_program_builder import ToyDBTraceBuilder

class DebuggerModulesPluginScreenShots(unittest.TestCase):

    def setUp(self):
        self.programManager = add_plugin(tool, ProgramManagerPlugin)
        self.traceManager = add_plugin(tool, DebuggerTraceManagerService)
        self.modulesPlugin = add_plugin(tool, DebuggerModulesPlugin)

        self.modulesProvider = waitForComponentProvider(DebuggerModulesProvider)
        self.tb = ToyDBTraceBuilder("echo", ToyProgramBuilder._X64)

    def tearDown(self):
        if hasattr(self, 'tb'):
            self.tb.close()
        if hasattr(self, 'progEcho') and self.progEcho is not None:
            self.progEcho.release(self)
        if hasattr(self, 'progLibC') and self.progLibC is not None:
            self.progLibC.release(self)

    def test_capture_debugger_modules_plugin(self):
        try:
            with UndoableTransaction(tid=self.tb.start_transaction()) as tid:
                snap = tb.trace.get_time_manager().create_snapshot("First").get_key()

                bin = tb(trace).add_loaded_module("/bin/bash", "/bin/bash",
                                               tb.range(0x00400000, 0x0060ffff), snap)
                bin.add_section("bash[.text]", ".text", tb.range(0x00400000, 0x0040ffff))
                bin.add_section("bash[.data]", ".data", tb.range(0x00600000, 0x0060ffff))

                lib = tb(trace).add_loaded_module("/lib/libc.so.6", "/lib/libc.so.6",
                                               tb.range(0x7fac0000, 0x7faeffff), snap)
                lib.add_section("libc[.text]", ".text", tb.range(0x7fac0000, 0x7facffff))
                lib.add_section("libc[.data]", ".data", tb.range(0x7fae0000, 0x7faeffff))

            self.trace_manager.open_trace(self.tb(trace))
            self.trace_manager.activate_trace(self.tb(trace))

            capture_isolated_provider(self.modulesProvider, 600, 600)
        except Exception as e:
            print(f"An error occurred: {str(e)}")

    def addr(program, offset):
        return program.get_address_factory().get_default_address_space().get_address(offset)

    def populate_trace_and_programs():
        root = tool.get_project().get_project_data().get_root_folder()
        try:
            with UndoableTransaction(tid=self.tb.start_transaction()) as tid:
                snap = tb.trace.get_time_manager().create_snapshot("First").get_key()

                bin = tb(trace).add_loaded_module("/bin/bash", "/bin/bash",
                                               tb.range(0x00400000, 0x0060ffff), snap)
                bin.add_section("bash[.text]", ".text", tb.range(0x00400000, 0x0040ffff))
                bin.add_section("bash[.data]", ".data", tb.range(0x00600000, 0x0060ffff))

                lib = tb(trace).add_loaded_module("/lib/libc.so.6", "/lib/libc.so.6",
                                               tb.range(0x7fac0000, 0x7faeffff), snap)
                lib.add_section("libc[.text]", ".text", tb.range(0x7fac0000, 0x7facffff))
                lib.add_section("libc[.data]", ".data", tb.range(0x7fae0000, 0x7faeffff))

            self.prog_echo = create_default_program("bash", ProgramBuilder._X64)
            self.prog_libc = create_default_program("libc.so.6", ProgramBuilder._X64)

            try:
                with UndoableTransaction(tid=self.prog_echo.start_transaction()) as tid:
                    self.prog_echo.set_image_base(addr(self.prog_echo, 0x00400000), True)
                    self.prog_echo.get_memory().create_initialized_block(".text",
                                                                           addr(self.prog_echo,
                                                                                0x00400000),
                                                                           0x10000, (byte) 0,
                                                                           TaskMonitor.DUMMY,
                                                                           False)

                try:
                    with UndoableTransaction(tid=self.prog_libc.start_transaction()) as tid:
                        self.prog_libc.set_image_base(addr(self.prog_libc, 0x00400000), True)
                        self.prog_libc.get_memory().create_initialized_block(".text",
                                                                               addr(self.prog_libc,
                                                                                    0x00400000),
                                                                           0x10000, (byte) 0,
                                                                           TaskMonitor.DUMMY,
                                                                           False)

                root.create_file("trace", tb.trace, TaskMonitor.DUMMY)
                root.create_file("echo", self.prog_echo, TaskMonitor.DUMMY)
                root.create_file("libc.so.6", self.prog_libc, TaskMonitor.DUMMY)

            try:
                with UndoableTransaction(tid=self.tb.start_transaction()) as tid:
                    trace_manager.open_trace(self.tb(trace))
                    trace_manager.activate_trace(self.tb(trace))

                    program_manager.open_program(self.prog_echo)
                    program_manager.open_program(self.prog_libc)
        except Exception as e:
            print(f"An error occurred: {str(e)}")

    def test_capture_debugger_module_map_proposal_dialog(self):
        self.populate_trace_and_programs()

        modules_provider.set_selected_modules(set.copyof(tb(trace).get_module_manager().get_all_modules()))
        perform_action(modules_provider.action_map_modules, False)

        capture_dialog(DebuggerModuleMapProposalDialog.class)
