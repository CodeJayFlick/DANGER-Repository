import unittest
from abc import ABC, abstractmethod


class AbstractDebuggerModelScenarioRegistersTest(ABC):
    @abstractmethod
    def get_specimen(self) -> None:
        pass

    @abstractmethod
    def post_launch(self, process: str) -> None:
        pass

    @abstractmethod
    def get_breakpoint_expression(self) -> str:
        pass

    @abstractmethod
    def get_register_writes(self) -> dict:
        pass

    @abstractmethod
    def verify_expected_effect(self, process: str) -> None:
        pass


class TestScenario(unittest.TestCase):
    def test_scenario(self):
        specimen = self.get_specimen()
        launcher = find_launcher()  # This method should be implemented in the subclass
        print("Launching", specimen)
        launcher.launch(specimen.get_launcher_args())
        print("Done launching")
        process = retry_for_process_running(specimen, self)  # This method should be implemented in the subclass
        post_launch(process)

        breakpoint_container = find_breakpoint_spec_container(process_path=process)  # This method should be implemented in the subclass
        print("Placing breakpoint")
        breakpoint_container.place_breakpoint(get_breakpoint_expression(), [TargetBreakpointKind.SW_EXECUTE])

        self.assertTrue(DebugModelConventions.is_process_alive(process))
        state = AsyncState(m.suitable(TargetExecutionStateful, process_path=process))

        for i in range(1):
            self.assertTrue(state.get().is_alive())
            print(f"({i}) Resuming process until breakpoint hit")
            resume(process)
            print("Done", i)
            wait_on(state.wait_until(lambda s: s != TargetExecutionState.RUNNING))
        self.assertTrue(state.get().is_alive())

        target = wait_on(trapped_future)  # This method should be implemented in the subclass
        to_write = get_register_writes()
        print(f"Writing registers: {to_write.keys()}")
        perform_register_writes(target, to_write)
        print("Done")

        self.assertTrue(DebugModelConventions.is_process_alive(process))

        for i in range(1):
            print(f"({i}) Resuming process until terminated")
            resume(process)
            print("Done", i)
            wait_on(state.wait_until(lambda s: s != TargetExecutionState.RUNNING))
            print("Parent state after resume-wait-not-running:", state)

        verify_expected_effect(process)


if __name__ == "__main__":
    unittest.main()
