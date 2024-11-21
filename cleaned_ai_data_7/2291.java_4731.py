import unittest
from ghidra.dbg import *
from ghidra.util import *

class AbstractDebuggerModelScenarioStackTest(unittest.TestCase):

    def get_specimen(self):
        # This method should be implemented by subclasses to return a specimen.
        pass

    def post_launch(self, process):
        # Perform any work needed after the specimen has been launched
        pass

    def get_breakpoint_expression(self):
        # Get the expression to break at the innermost recognizable function
        pass

    def validate_frame_pc(self, index, pc):
        # Examine the address of the given frame and verify it is where expected
        pass

    @unittest.skip("This test needs implementation")
    def test_scenario(self):

        specimen = self.get_specimen()
        bp_monitor = AnnotatedDebuggerAttributeListener()

        for state in AsyncState:
            if state == TargetExecutionStateful.STATE_STOPPED:
                break

        process = retry_for_process_running(specimen, self)
        post_launch(process)

        breakpoint_container = find_breakpoint_spec_container(process.path)
        wait_on(breakpoint_container.place_breakpoint(self.get_breakpoint_expression(), set([TargetBreakpointKind.SW_EXECUTE])))

        for i in range(1):
            resume(process)
            state = new AsyncState(suitable(TargetExecutionStateful, process.path))
            while not bp_monitor.hit:
                self.assertTrue(state.get().is_alive())
                msg.debug("({} {}) Resuming process until breakpoint hit".format(i, "Done"))
                wait_on(state.wait_until(lambda s: s != TargetExecutionState.RUNNING))

        stack = find_stack(process.path)
        matcher = stack.schema.search_for(TargetStackFrame, True).get_singleton_pattern()
        self.assertIsNotNone(pattern)
        self.assertEqual(1, pattern.count_wildcards())

        frames = retry(lambda: list(m.find_all(TargetStackFrame, stack.path, True)))
        for i in range(4):
            f = frames[i]
            validate_frame_pc(i, f.program_counter)

    def test(self):

        # This method should be implemented by subclasses to run the scenario.
        pass

if __name__ == "__main__":
    unittest.main()
