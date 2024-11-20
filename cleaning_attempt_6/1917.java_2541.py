import unittest
from ghidra import dbg, target
from ghidra.dbg.util.path_pattern import PathPattern
from collections import defaultdict

class AbstractModelForLldbThreadActivationTest:
    def __init__(self):
        pass

    def get_thread_pattern(self):
        # This method should be implemented in the subclass.
        raise NotImplementedError("get_thread_pattern must be implemented")

    def get_specimen(self):
        return "MacOSSpecimen.PRINT"

    def get_count(self):
        return 1

    def get_expected_session_path(self):
        # This method should be implemented in the subclass.
        raise NotImplementedError("get_expected_session_path must be implemented")

    @unittest.skip
    def test_activate_via_interpreter(self):
        specimen = self.get_specimen()
        launcher = find_launcher()  # This function is not defined here, it's assumed to exist elsewhere.
        count = self.get_count()

        for i in range(count):
            wait_on(launcher.launch(specimen))

        m = getModel()  # This method is not defined here, it's assumed to exist elsewhere.

        wait_settled(m.getModel(), 200)

    @unittest.skip
    def test_activate_via_interpreter(self):
        obj = self.get_expected_session_path()
        interpreter = find_interpreter()  # This function is not defined here, it's assumed to exist elsewhere.
        thread = LldbModelTargetThread(obj)
        sbt = SBThread(thread.getModelObject())
        index = sbt.getIndexID()

        wait_on(interpreter.execute("thread select " + str(index)))

    def get_id_from_capture(self, line):
        # This method should be implemented in the subclass.
        raise NotImplementedError("get_id_from_capture must be implemented")

    @unittest.skip
    def test_assert_active_via_interpreter(self):
        expected = self.get_expected_session_path()
        interpreter = find_interpreter()  # This function is not defined here, it's assumed to exist elsewhere.

        output = wait_on(interpreter.executeCapture("thread list"))
        line = next((l for l in output.split("\n") if l.strip().startswith("*")), None).strip()

        thread_id = self.get_id_from_capture(line)
        exp_id = get_thread_pattern().matchIndices(expected)[2]
        assertEqual(exp_id, thread_id)

if __name__ == "__main__":
    unittest.main()
