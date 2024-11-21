import re
from typing import List

class AbstractModelForGdbBreakpointsTest:
    BREAK_PATTERN = re.compile("Breakpoints\\[]")

    def get_test(self):
        return self

    def get_launch_specimen(self):
        return "GdbLinuxSpecimen.PRINT"

    def get_expected_breakpoint_container_path(self, target_path: List[str]) -> List[str]:
        return ["Breakpoints"]

    def get_expected_supported_kinds(self) -> set:
        return {
            TargetBreakpointKind.SW_EXECUTE,
            TargetBreakpointKind.HW_EXECUTE,
            TargetBreakpointKind.READ,
            TargetBreakpointKind.WRITE
        }

    def get_suitable_range_for_breakpoint(self, target: str, kind: int) -> tuple:
        frame = self.retry(lambda: self.find_any_stack_frame(target))
        self.wait_on(frame.fetch_attributes())
        pc = frame.get_program_counter().add(16)
        if kind in [TargetBreakpointKind.SW_EXECUTE, TargetBreakpointKind.HW_EXECUTE]:
            return (pc, pc)
        elif kind in [TargetBreakpointKind.READ, TargetBreakpointKind.WRITE]:
            return (pc, pc + 4)

    def place_breakpoint_via_interpreter(self, range: tuple, kind: int, interpreter: str) -> None:
        min_addr = range[0]
        if len(range) == 4:
            if kind in [TargetBreakpointKind.READ, TargetBreakpointKind.WRITE]:
                self.wait_on(interpreter.execute(f"rwatch -l *((int*) 0x{min_addr}))"))
            else:
                raise AssertionError
        elif len(range) == 1:
            if kind in [TargetBreakpointKind.SW_EXECUTE, TargetBreakpointKind.HW_EXECUTE]:
                self.wait_on(interpreter.execute(f"break *0x{min_addr}")))
            else:
                raise AssertionError

    def disable_via_interpreter(self, target: str, interpreter: str) -> None:
        assert isinstance(target, dict)
        index = re.search(self.BREAK_PATTERN, target["path"]).group(1)
        self.wait_on(interpreter.execute(f"disable {index}"))

    def enable_via_interpreter(self, target: str, interpreter: str) -> None:
        assert isinstance(target, dict)
        index = re.search(self.BREAK_PATTERN, target["path"]).group(1)
        self.wait_on(interpreter.execute(f"enable {index}"))

    def delete_via_interpreter(self, target: str, interpreter: str) -> None:
        assert isinstance(target, dict)
        index = re.search(self.BREAK_PATTERN, target["path"]).group(1)
        self.wait_on(interpreter.execute(f"delete {index}"))

    def assert_loc_covers_via_interpreter(self, range: tuple, kind: int, loc: str, interpreter: str) -> None:
        index = re.search(self.BREAK_PATTERN, loc).group(1)
        output = self.wait_on(interpreter.executeCapture(f"info break {index}"))
        line = next(line for line in output.split("\n") if not line.startswith("Num")).strip()
        assert line.startswith(index)

    def assert_enabled_via_interpreter(self, target: str, enabled: bool, interpreter: str) -> None:
        assert isinstance(target, dict)
        index = re.search(self.BREAK_PATTERN, target["path"]).group(1)
        output = self.wait_on(interpreter.executeCapture(f"info break {index}"))
        line = next(line for line in output.split("\n") if not line.startswith("Num")).strip()
        enb = line.split("keep")[1].strip().split()[0]
        assert enb == "y" if enabled else "n"

    def assert_deleted_via_interpreter(self, target: str, interpreter: str) -> None:
        assert isinstance(target, dict)
        index = re.search(self.BREAK_PATTERN, target["path"]).group(1)
        output = self.wait_on(interpreter.executeCapture(f"info break {index}"))
        assert "No breakpoint" in output

    def retry(self, func):
        for _ in range(10):
            try:
                return func()
            except AssertionError as e:
                print(e)

    def wait_on(self, command: str) -> None:
        # This function should be implemented based on the actual requirements
        pass

    def find_any_stack_frame(self, target: str) -> dict:
        # This function should be implemented based on the actual requirements
        return {}
