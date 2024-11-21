class InVmModelForLldbBreakpointsTest:
    def __init__(self):
        pass

    def get_break_pattern(self):
        return PathPattern("Sessions[].Debug.Breakpoints[]")

    def model_host(self) -> 'InVmLldbModelHost':
        return InVmLldbModelHost()

# The following tests are being ignored because the target doesn't generate
#   breakpointAdded/Modified events on placement, only on resume

class TestPlaceSoftwareExecuteBreakpointViaInterpreter(unittest.TestCase):
    @unittest.skip("Target doesn't generate breakpointAdded/Modified events on placement")
    def test_place_software_execute_breakpoint_via_interpreter(self):
        super().test_place_software_execute_breakpoint_via_interpreter()

class TestPlaceHardwareExecuteBreakpointViaInterpreter(unittest.TestCase):
    @unittest.skip("Target doesn't generate breakpointAdded/Modified events on placement")
    def test_place_hardware_execute_breakpoint_via_interpreter(self):
        super().test_place_hardware_execute_breakpoint_via_interpreter()

class TestPlaceReadBreakpointViaInterpreter(unittest.TestCase):
    @unittest.skip("Target doesn't generate breakpointAdded/Modified events on placement")
    def test_place_read_breakpoint_via_interpreter(self):
        super().test_place_read_breakpoint_via_interpreter()

class TestPlaceWriteBreakpointViaInterpreter(unittest.TestCase):
    @unittest.skip("Target doesn't generate breakpointAdded/Modified events on placement")
    def test_place_write_breakpoint_via_interpreter(self):
        super().test_place_write_breakpoint_via_interpreter()

class TestDeleteBreakpointsViaInterpreter(unittest.TestCase):
    @unittest.skip("Target doesn't generate breakpointAdded/Modified events on placement")
    def test_delete_breakpoints_via_interpreter(self):
        super().test_delete_breakpoints_via_interpreter()

class TestDeleteBreakpointLocationsViaInterpreter(unittest.TestCase):
    @unittest.skip("Target doesn't generate breakpointAdded/Modified events on placement")
    def test_delete_breakpoint_locations_via_interpreter(self):
        super().test_delete_breakpoint_locations_via_interpreter()

class TestToggleBreakpointsViaInterpreter(unittest.TestCase):
    @unittest.skip("Target doesn't generate breakpointAdded/Modified events on placement")
    def test_toggle_breakpoints_via_interpreter(self):
        super().test_toggle_breakpoints_via_interpreter()

class TestToggleBreakpointLocationsViaInterpreter(unittest.TestCase):
    @unittest.skip("Target doesn't generate breakpointAdded/Modified events on placement")
    def test_toggle_breakpoint_locations_via_interpreter(self):
        super().test_toggle_breakpoint_locations_via_interpreter()


# These have a similar problem enabled/disabled & cleared for watchpoints
#   appear to occur on resume

class TestDeleteBreakpoints(unittest.TestCase):
    @unittest.skip("Target doesn't generate breakpointAdded/Modified events on placement")
    def test_delete_breakpoints(self):
        super().test_delete_breakpoints()

class TestToggleBreakpoints(unittest.TestCase):
    @unittest.skip("Target doesn't generate breakpointAdded/Modified events on placement")
    def test_toggle_breakpoints(self):
        super().test_toggle_breakpoints()
