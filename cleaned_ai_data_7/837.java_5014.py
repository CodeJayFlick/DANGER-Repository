class AbstractModelForDbgengBreakpointsTest:
    def __init__(self):
        pass

    def get_break_pattern(self):
        # This method should be implemented in subclass.
        raise NotImplementedError("Method 'get_break_pattern' must be implemented.")

    @property
    def break_id_pos(self):
        return 1

    def get_test(self):
        return self

    def seed_path(self):
        return []

    def get_launch_specimen(self):
        # This method should be implemented in subclass.
        raise NotImplementedError("Method 'get_launch_specimen' must be implemented.")

    def get_expected_breakpoint_container_path(self, target_path):
        import pathutils
        return pathutils.extend(target_path, ["Debug", "Breakpoints"])

    def get_expected_supported_kinds(self):
        from enum import Enum

        class TargetBreakpointKind(Enum):
            SW_EXECUTE = 1
            HW_EXECUTE = 2
            READ = 3
            WRITE = 4

        return {TargetBreakpointKind.SW_EXECUTE, TargetBreakpointKind.HW_EXECUTE,
                TargetBreakpointKind.READ, TargetBreakpointKind.WRITE}

    def get_suitable_range_for_breakpoint(self, target, kind):
        # This method should be implemented in subclass.
        raise NotImplementedError("Method 'get_suitable_range_for_breakpoint' must be implemented.")

    def place_breakpoint_via_interpreter(self, range, kind, interpreter):
        min_addr = range[0]
        if len(range) == 4:
            if kind == TargetBreakpointKind.READ or kind == TargetBreakpointKind.WRITE:
                # This method should be implemented in subclass.
                raise NotImplementedError("Method 'place_breakpoint_via_interpreter' must be implemented.")
            else:
                # This method should be implemented in subclass.
                raise NotImplementedError("Method 'place_breakpoint_via_interpreter' must be implemented.")
        elif len(range) == 1:
            if kind == TargetBreakpointKind.SW_EXECUTE or kind == TargetBreakpointKind.HW_EXECUTE:
                # This method should be implemented in subclass.
                raise NotImplementedError("Method 'place_breakpoint_via_interpreter' must be implemented.")
            else:
                # This method should be implemented in subclass.
                raise NotImplementedError("Method 'place_breakpoint_via_interpreter' must be implemented.")
        else:
            # This method should be implemented in subclass.
            raise NotImplementedError("Method 'place_breakpoint_via_interpreter' must be implemented.")

    def disable_via_interpreter(self, target_togglable, interpreter):
        bp_id = self.get_break_pattern().match_indices(target_togglable.path)[self.break_id_pos]
        # This method should be implemented in subclass.
        raise NotImplementedError("Method 'disable_via_interpreter' must be implemented.")

    def enable_via_interpreter(self, target_togglable, interpreter):
        bp_id = self.get_break_pattern().match_indices(target_togglable.path)[self.break_id_pos]
        # This method should be implemented in subclass.
        raise NotImplementedError("Method 'enable_via_interpreter' must be implemented.")

    def delete_via_interpreter(self, target_deletable, interpreter):
        bp_id = self.get_break_pattern().match_indices(target_deletable.path)[self.break_id_pos]
        # This method should be implemented in subclass.
        raise NotImplementedError("Method 'delete_via_interpreter' must be implemented.")

    def assert_loc_covers_via_interpreter(self, range, kind, loc, interpreter):
        bp_id = self.get_break_pattern().match_indices(loc.path)[self.break_id_pos]
        line = interpreter.execute_capture(f"bl {bp_id}").strip()
        self.assertFalse(line.startswith("\n"))
        self.assertTrue(line.startswith(bp_id))
        # TODO: Do I care to parse the details? The ID is confirmed, and details via the object...
        pass

    def assert_enabled_via_interpreter(self, target_togglable, enabled, interpreter):
        bp_id = self.get_break_pattern().match_indices(target_togglable.path)[self.break_id_pos]
        line = interpreter.execute_capture(f"bl {bp_id}").strip()
        self.assertFalse(line.startswith("\n"))
        self.assertTrue(line.startswith(bp_id))
        e = line.split()[1]
        if enabled:
            self.assertEqual("e", e)
        else:
            self.assertEqual("d", e)

    def assert_deleted_via_interpreter(self, target_deletable, interpreter):
        bp_id = self.get_break_pattern().match_indices(target_deletable.path)[self.break_id_pos]
        line = interpreter.execute_capture(f"bl {bp_id}").strip()
        self.assertEqual("", line)
