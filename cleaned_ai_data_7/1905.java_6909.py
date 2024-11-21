import unittest
from ghidra_dbg_target import *
from ghidra_dbg_util_path_pattern import PathPattern
from ghidra_dbg_target_launcher import TargetLauncher
from ghidra_dbg_target_process import TargetProcess
from ghidra_dbg_model import Model

class AbstractModelForLldbFrameActivationTest:
    def __init__(self):
        pass

    def get_stack_pattern(self):
        # implement this method to return a PathPattern object
        pass

    def get_specimen(self):
        return "MacOSSpecimen.STACK"

    def get_activatable_things(self) -> list[TargetObject]:
        specimen = self.get_specimen()
        launcher = find_launcher()  # root launcher should generate new inferiors
        wait_on(launcher.launch(specimen.split(',')))

        process = retry(lambda: m.find_any(TargetProcess, seed_path()), [AssertionError])

        assert process is not None

        trap_at("break_here", process)

        wait_settled(m.get_model(), 200)

        frames = retry(lambda: m.find_all(TargetStackFrame, seed_path(), True), [AssertionError])
        self.assertTrue(len(frames) >= 3)
        return list(map(lambda x: x.value, frames))

    def activate_via_interpreter(self, obj: TargetObject, interpreter: TargetInterpreter):
        index = get_stack_pattern().match_indices(obj.path)[2]
        wait_on(interpreter.execute(f"frame select {index}"))

    @abstractmethod
    def get_id_from_capture(self, line: str) -> str:
        pass

    def assert_active_via_interpreter(self, expected: TargetObject, interpreter: TargetInterpreter):
        line = wait_on(interpreter.execute_capture("frame info")).strip()
        self.assertFalse(line.__contains__("\n"))
        id = self.get_id_from_capture(line)
        frame_id = int(id, 10)
        exp_id = int(get_stack_pattern().match_indices(expected.path)[2], 10)
        self.assertEqual(exp_id, frame_id)

if __name__ == "__main__":
    unittest.main()
