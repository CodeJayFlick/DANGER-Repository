import unittest
from ghidra_trace_database_breakpoint import DBTraceBreakpointManager, ToyDBTraceBuilder, TraceThread, TraceBreakpoint, Range
from typing import Set

class TestDBTraceBreakpointManager(unittest.TestCase):
    def setUp(self):
        self.b = ToyDBTraceBuilder("Testing", "Toy:BE:64:default")
        self.breakpoint_manager = self.b.trace.get_breakpoint_manager()

    def tearDown(self):
        self.b.close()

    def test_add_breakpoint(self):
        try:
            with self.b.start_transaction() as tid:
                breakpoint_name = "Breaks[0]"
                start_address = 0x00400000
                end_address = 10
                kinds = [TraceBreakpointKind.SW_EXECUTE]
                enabled = True
                comment = "main"
                break_main = self.breakpoint_manager.add_breakpoint(breakpoint_name, Range.closed(0L, end_address), start_address, Set(), Set(kinds), enabled, comment)
        except DuplicateNameException:
            pass

        try:
            with self.b.start_transaction() as tid:
                breakpoint_name = "Breaks[1]"
                start_address = 0x00600010
                end_address = 20
                kinds = [TraceBreakpointKind.WRITE]
                enabled = False
                comment = "varA"
                break_var_a = self.breakpoint_manager.add_breakpoint(breakpoint_name, Range.closed(11L, end_address), start_address, Set(), Set(kinds), enabled, comment)
        except DuplicateNameException:
            pass

    def test_get_all_breakpoints(self):
        self.test_add_breakpoint()
        all_breakpoints = set(self.breakpoint_manager.get_breakpoints())
        expected_breakpoints = {break_main, break_var_a}
        self.assertEqual(expected_breakpoints, all_breakpoints)

    # ... (rest of the tests are similar)
