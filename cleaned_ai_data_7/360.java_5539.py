import unittest
from ghidra_app_plugin_core_bookmark import BookmarkPlugin
from ghidra_app_plugin_core_byteviewer import ByteViewerPlugin
from ghidra_app_plugin_core_clear import ClearPlugin
from ghidra_app_plugin_core_comments import CommentsPlugin
from ghidra_app_plugin_core_data import DataPlugin
from ghidra_app_plugin_core_debug_gui_breakpoint import DebuggerBreakpointMarkerPlugin, DebuggerBreakpointsPlugin
from ghidra_app_plugin_core_debug_gui_listing import DebuggerListingPlugin
from ghidra_app_plugin_core_debug_gui_modules import DebuggerModulesPlugin
from ghidra_app_plugin_core_debug_gui_register import DebuggerRegistersPlugin
from ghidra_app_plugin_core_debug_gui_target import DebuggerTargetsPlugin
from ghidra_app_plugin_core_debug_gui_thread import DebuggerThreadsPlugin
from ghidra_app_plugin_core_debug_gui_time import DebuggerTimePlugin
from ghidra_app_plugin_core_disassembler import DisassemblerPlugin
from ghidra_app_plugin_core_equate import EquatePlugin
from ghidra_app_plugin_core_function import FunctionPlugin
from ghidra_app_plugin_core_label import LabelMgrPlugin
from ghidra_app_plugin_core_symtable import SymbolTablePlugin

class DebuggerManualTest(unittest.TestCase):
    def setUp(self):
        self.ub = ToyDBTraceBuilder("dynamic2-" + type(self).__name__, LANGID_TOYBE64)
        try:
            with UndoableTransaction() as tid:
                ub.trace.getTimeManager().createSnapshot("First snap")
        except Exception as e:
            print(f"Error: {e}")

    def tearDown(self):
        if self.ub is not None:
            if trace_manager.getOpenTraces().contains(ub.trace):
                trace_manager.closeTrace(ub.trace)
            self.ub.close()

    @unittest.skip
    def testManual01(self):
        tool = ghidra_app_plugin_core_debug_gui_breakpoint.DebuggerBreakpointMarkerPlugin()
        add_plugins(tool, [
            DebuggerBreakpointsPlugin,
            DebuggerListingPlugin,
            DebuggerModulesPlugin,
            DebuggerRegistersPlugin,
            #DebuggerRegsListingPlugin,
            DebuggerTargetsPlugin,
            DebuggerThreadsPlugin,
            DebuggerTimePlugin,
            DebuggerWorkflowServiceProxyPlugin,

            ByteViewerPlugin,
            BookmarkPlugin,
            ClearPlugin,
            CommentsPlugin,
            DisassemblerPlugin,
            DataPlugin,
            EquatePlugin,
            FunctionPlugin,
            LabelMgrPlugin,
            SymbolTablePlugin
        ])

        try:
            with UndoableTransaction() as tid:
                tb.trace.getMemoryManager().createRegion("Region", 0, tb.range(0x4000, 0x4fff), TraceMemoryFlag.READ | TraceMemoryFlag.EXECUTE)
                tb(trace).getThreadManager().createThread("Thread 1", 0)
                tb(trace).getThreadManager().createThread("Thread 2", 4)

                tb.addData(0, tb.addr(0x4004), Undefined4DataType.dataType, tb.buf(6, 7, 8, 9))
                tb.addInstruction(0, tb.addr(0x4008), tb.language, tb.buf(0xf4, 0))

                x86 = getSLEIGH_X86_LANGUAGE()
                guest = tb(trace).getLanguageManager().addGuestLanguage(x86)
                guest.addMappedRange(tb.addr(0x4000), guest.addr(0x00400000), 0x1000)
                tb.addInstruction(0, tb.addr(0x400a), x86, tb.buf(0x90))
        except Exception as e:
            print(f"Error: {e}")

        waitForSwing()
        traceManager.openTrace(tb.trace)
        traceManager.openTrace(ub(trace).trace)
        traceManager.activateTrace(tb(trace).trace)

        while tool.isVisible():
            time.sleep(1.0)

if __name__ == "__main__":
    unittest.main()

