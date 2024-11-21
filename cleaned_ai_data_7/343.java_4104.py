import unittest
from ghidra import GhidraScreenShotGenerator


class DebuggerRegionsPluginScreenShots(GhidraScreenShotGenerator):
    def setUp(self):
        self.trace_manager = add_plugin(tool, DebuggerTraceManagerServicePlugin)
        self.regions_plugin = add_plugin(tool, DebuggerRegionsPlugin)

        tb = ToyDBTraceBuilder("echo", _X64)
        return tb

    def tearDown(self):
        tb.close()

    @unittest.skip
    def test_capture_debugger_regions_plugin(self):
        try:
            tid = tb.start_transaction()
            snap = tb.trace.get_time_manager().create_snapshot("First").get_key()

            tb(trace).add_region("[400000:40ffff]", Range.at_least(snap), 
                                tb.range(0x00400000, 0x0040ffff),
                                {TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE})

            tb(trace).add_region("[600000:60ffff]", Range.at_least(snap), 
                                tb.range(0x00600000, 0x0060ffff),
                                {TraceMemoryFlag.READ, TraceMemoryFlag.WRITE})

            tb(trace).add_region("[7fac0000:7facffff]", Range.at_least(snap), 
                                tb.range(0x7fac0000, 0x7facffff),
                                {TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE})

            tb(trace).add_region("[7fae0000:7faeffff]", Range.at_least(snap), 
                                tb.range(0x7fae0000, 0x7faeffff),
                                {TraceMemoryFlag.READ, TraceMemoryFlag.WRITE})

            trace_manager.open_trace(tb.trace)
            trace_manager.activate_trace(tb(trace))

            capture_isolated_provider(DebuggerRegionsProvider, 900, 300)

        except Exception as e:
            print(f"An error occurred: {e}")
