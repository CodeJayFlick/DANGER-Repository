Here is the translation of the Java code into Python:

```Python
class PCLocationTrackingSpec:
    CONFIG_NAME = "TRACK_PC"

    def get_config_name(self):
        return self.CONFIG_NAME

    def get_menu_name(self):
        return TrackLocationAction.NAME_PC

    def get_menu_icon(self):
        return TrackLocationAction.ICON_PC

    def compute_register(self, coordinates):
        trace = coordinates.get_trace()
        if trace is None:
            return None
        return trace.get_base_language().get_program_counter()

    def compute_default_address_space(self, coordinates):
        return coordinates.get_trace().get_base_language().get_default_space()

    def compute_pcvia_stack(self, coordinates):
        trace = coordinates.get_trace()
        thread = coordinates.get_thread()
        snap = coordinates.get_snap()
        stack = trace.get_stack_manager().get_latest_stack(thread, snap)
        if stack is None:
            return None
        level = coordinates.get_frame()
        frame = stack.get_frame(level, False)
        if frame is None:
            return None
        return frame.get_program_counter()

    def compute_trace_address(self, tool, coordinates, emu_snap):
        if coordinates.get_time().is_snap_only():
            pc = self.compute_pcvia_stack(coordinates)
            if pc is not None:
                return pc
        return super().compute_trace_address(tool, coordinates, emu_snap)

    def affected_by_stack_change(self, stack, coordinates):
        if stack.get_thread() != coordinates.get_thread():
            return False
        if not coordinates.get_time().is_snap_only():
            return False
        cur_stack = coordinates.get_trace().get_stack_manager().get_latest_stack(stack.get_thread(), coordinates.get_snap())
        if stack is not None and cur_stack is not None:
            return True
        return False

class TrackLocationAction:
    NAME_PC = "PC"
    ICON_PC = ""  # This should be replaced with the actual icon path or a placeholder.

super() refers to the parent class, which in this case would be RegisterLocationTrackingSpec.