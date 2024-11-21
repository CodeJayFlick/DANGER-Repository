Here is the translation of the Java code into equivalent Python:

```Python
import ghidra.app.plugin.core.debug.gui.stack as stack_plugin
from org.junit import *
from com.google.common.collect.Range import *

class DebuggerStackPluginScreenShots:
    def __init__(self):
        self.program_manager = None
        self.trace_manager = None
        self.mapping_service = None
        self.stack_plugin = None
        self.stack_provider = None
        self.tb = None
        self.program = None

    @classmethod
    def setUpMine(cls, tool):
        cls.program_manager = add_plugin(tool, ProgramManagerPlugin)
        cls.trace_manager = add_plugin(tool, DebuggerTraceManagerServicePlugin)
        cls.mapping_service = add_plugin(tool, DebuggerStaticMappingServicePlugin)
        cls.stack_plugin = add_plugin(tool, stack_plugin.DebuggerStackPlugin)

    @classmethod
    def tearDownMine(cls):
        if cls.tb is not None:
            cls.tb.close()
        if cls.program is not None:
            cls.program.release()

    @staticmethod
    def addr(program, offset):
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

    @staticmethod
    def set(program, min, max):
        return AddressSetView(addr(program, min), addr(program, max))

    @classmethod
    def test_capture_debugger_stack_plugin(cls, tool):
        root = tool.getProject().getProjectData().getRootFolder()
        program = create_default_program("echo", ToyProgramBuilder._X64)
        try:
            with UndoableTransaction.start(program, "Populate", True) as tid:
                program.setImageBase(addr(program, 0x00400000), True)
                program.getMemory().createInitializedBlock(".text", addr(program, 0x00400000), 0x10000, (byte) 0, TaskMonitor.DUMMY, False)
                function_manager = program.getFunctionManager()
                function_manager.create_function("FUN_00401000", addr(0x00401000), set(program, 0x00401000, 0x00401100), SourceType.USER_DEFINED)
                function_manager.create_function("FUN_00401200", addr(0x00401200), set(program, 0x00401200, 0x00401300), SourceType.USER_DEFINED)
                function_manager.create_function("FUN_00404300", addr(0x00404300), set(program, 0x00404300, 0x00404400), SourceType.USER_DEFINED)

            snap = tb.trace.getTimeManager().create_snapshot("First").get_key()
            thread = tb.get_or_add_thread("[1]", snap)
            stack = tb.trace.get_stack_manager().get_stack(thread, snap, True)
            stack.set_depth(3, True)

            frame = stack.get_frame(0, False)
            frame.set_program_counter(tb.addr(0x00404321))
            frame = stack.get_frame(1, False)
            frame.set_program_counter(tb.addr(0x00401234))
            frame = stack.get_frame(2, False)
            frame.set_program_counter(tb.addr(0x00401001))

        finally:
            root.create_file("trace", tb.trace, TaskMonitor.DUMMY)
            root.create_file("echo", program, TaskMonitor.DUMMY)

    @classmethod
    def capture_isolated_provider(cls):
        stack_plugin.capture_isolated_provider(DebuggerStackProvider.class, 600, 300)


if __name__ == "__main__":
    tool = None
    DebuggerStackPluginScreenShots.setUpMine(tool)
    test_capture_debugger_stack_plugin(tool)
```

Please note that Python does not support direct translation of Java code. It requires manual conversion and might result in different behavior or functionality compared to the original Java code.