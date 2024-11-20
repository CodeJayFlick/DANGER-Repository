import unittest
from ghidra.dbg.target import *
from ghidra.dbg.test import AbstractDebuggerModelActivationTest
from java.util.stream import Stream
from java.util import Set, Map, List

class AbstractModelForDbgengProcessActivationTest(AbstractDebuggerModelActivationTest):
    def get_process_pattern(self):
        pass  # abstract method implementation is left to the subclass

    def get_count(self):
        return 3

    def get_specimen(self):
        return "WindowsSpecimen.PRINT"

    def get_expected_session_path(self):
        pass  # abstract method implementation is left to the subclass

    @unittest.skip
    def test_activatable_things(self):
        specimen = self.get_specimen()
        launcher = self.find_launcher()  # assuming this method exists in a superclass or elsewhere
        count = self.get_count()

        for i in range(count):
            self.wait_on(launcher.launch(specimen))

        self.wait_settled(self.model, 200)

    @unittest.skip
    def test_activate_via_interpreter(self):
        obj = None  # assuming this variable is set somewhere else
        interpreter = None  # assuming this variable is set somewhere else

        id_ = self.get_process_pattern().match_indices(obj.path)[0]
        self.wait_on(interpreter.execute(f"|{id_} s"))

    @unittest.skip
    def test_assert_active_via_interpreter(self):
        expected = None  # assuming this variable is set somewhere else
        interpreter = None  # assuming this variable is set somewhere else

        output = self.wait_on(interpreter.execute_capture("|"))
        line = next((l for l in output.split("\n") if l.strip().startswith(".")), None).strip()
        proc_id = self.get_id_from_capture(line)
        self.assertEqual(expected.path, 
            self.get_process_pattern().apply_indices(proc_id).get_singleton_path())

    def get_id_from_capture(self, line):
        pass  # abstract method implementation is left to the subclass
