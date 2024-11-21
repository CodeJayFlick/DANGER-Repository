class AbstractModelForLldbBreakpointsTest:
    def __init__(self):
        pass

    def get_break_pattern(self):
        # Implement this method in your subclass.
        raise NotImplementedError("get_break_pattern must be implemented")

    @property
    def test(self):
        return self

    def seed_path(self):
        return []

    def launch_specimen(self):
        return "MacOSSpecimen.PRINT"

    def get_expected_breakpoint_container_path(self, target_path):
        procs_path = PathUtils.parent(target_path)
        session_path = PathUtils.parent(procs_path)
        return PathUtils.extend(session_path, ["Debug", "Breakpoints"])

    def get_expected_supported_kinds(self):
        return {
            TargetBreakpointKind.SW_EXECUTE: True,
            #TargetBreakpointKind.HW_EXECUTE: True,
            TargetBreakpointKind.READ: True,
            TargetBreakpointKind.WRITE: True
        }

    def suitable_range_for_breakpoint(self, target, kind):
        frame = self.retry(lambda: find_any_stack_frame(target.path))
        if not frame:
            raise AssertionError("No stack frame found")
        pc = frame.program_counter
        wait_on(frame.fetch_attributes())
        return AddressRangeImpl(pc, pc)

    @staticmethod
    def place_breakpoint_via_interpreter(range, kind, interpreter):
        min_addr = range.min_address
        if range.length == 4:
            if kind in [TargetBreakpointKind.READ, TargetBreakpointKind.WRITE]:
                wait_on(interpreter.execute(f"watchpoint set expression -w {kind.name.lower()} -- {min_addr}"))
            else:
                raise AssertionError("Invalid breakpoint kind")
        elif range.length == 1:
            if kind in [TargetBreakpointKind.SW_EXECUTE, TargetBreakpointKind.HW_EXECUTE]:
                wait_on(interpreter.execute(f"breakpoint set {-kind.name.lower()} -a {min_addr}"))
            else:
                raise AssertionError("Invalid breakpoint kind")
        else:
            raise AssertionError("Invalid range length")

    @staticmethod
    def get_type_from_spec(t):
        if isinstance(t, LldbModelTargetBreakpointSpec):
            return "breakpoint"
        elif isinstance(t, LldbModelTargetWatchpointSpec):
            return "watchpoint"

    @staticmethod
    def get_command(cmd, type, bp_id):
        return f"{type} {cmd} {bp_id[1:]}

    def disable_via_interpreter(self, t, interpreter):
        bp_id = self.get_break_pattern().match_indices(t.path)[0]
        type = self.get_type_from_spec(t)
        wait_on(interpreter.execute(f"disable {self.get_command('disable', type, bp_id)}"))

    def enable_via_interpreter(self, t, interpreter):
        bp_id = self.get_break_pattern().match_indices(t.path)[0]
        type = self.get_type_from_spec(t)
        wait_on(interpreter.execute(f"enable {self.get_command('enable', type, bp_id)}"))

    def delete_via_interpreter(self, d, interpreter):
        bp_id = self.get_break_pattern().match_indices(d.path)[0]
        type = self.get_type_from_spec(d)
        wait_on(interpreter.execute(f"delete {self.get_command('delete', type, bp_id)}"))

    @staticmethod
    def assert_loc_covers_via_interpreter(range, kind, loc, interpreter):
        match_indices = self.get_break_pattern().match_indices(loc.specification.path)[0]
        bp_id = match_indices[1:]
        type = "breakpoint" if kind in [TargetBreakpointKind.SW_EXECUTE, TargetBreakpointKind.HW_EXECUTE] else "watchpoint"
        line = wait_on(interpreter.execute_capture(self.get_command("list", type, bp_id))).strip()
        assert line.startswith(bp_id), f"{line} does not start with {bp_id}"
        if kind in [TargetBreakpointKind.SW_EXECUTE, TargetBreakpointKind.HW_EXECUTE]:
            assert line.endswith(f":{bp_id[1:]}"), f"{line} does not end with :{bp_id[1:]}"
        else:
            assert bp_id.lower() in line, f"{line} does not contain {bp_id}"

    @staticmethod
    def assert_enabled_via_interpreter(t, enabled, interpreter):
        bp_id = self.get_break_pattern().match_indices(t.path)[0]
        type = "breakpoint" if isinstance(t, LldbModelTargetBreakpointSpec) else "watchpoint"
        line = wait_on(interpreter.execute_capture(self.get_command("list", type, bp_id))).strip()
        assert f"{bp_id[1:]}:" in line, f"{line} does not contain {bp_id}"
        if enabled:
            assert ":disable" not in line, f":{bp_id[1:]}, disable"
        else:
            assert ":enable" not in line, f":{bp_id[1:]}, enable"

    @staticmethod
    def assert_deleted_via_interpreter(d, interpreter):
        bp_id = self.get_break_pattern().match_indices(d.path)[0]
        type = "breakpoint" if isinstance(d, LldbModelTargetBreakpointSpec) else "watchpoint"
        line = wait_on(interpreter.execute_capture(type)).strip()
        assert f"{bp_id[1:]}:" not in line, f"{line} contains {bp_id}"
