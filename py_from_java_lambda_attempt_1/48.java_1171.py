Here is the translation of the Java interface `RegisterLocationTrackingSpec` into a Python class:

```Python
class RegisterLocationTrackingSpec:
    def compute_register(self, coordinates):
        # TO DO: implement this method
        pass

    def compute_default_address_space(self, coordinates):
        # TO DO: implement this method
        pass

    def compute_title(self, coordinates):
        register = self.compute_register(coordinates)
        if register is None:
            return None
        return register.name

    def compute_trace_address(self, tool, coordinates, emu_snap):
        trace = coordinates.get_trace()
        thread = coordinates.get_thread()
        snap = coordinates.get_snap()
        frame = coordinates.get_frame()
        reg = self.compute_register(coordinates)
        if reg is None:
            return None
        if not thread.get_lifespan().contains(snap):
            return None
        regs = trace.get_memory_manager().get_memory_register_space(thread, frame, False)
        if regs is None:
            return None
        value = None
        state = regs.get_state(emu_snap, reg)
        if state == TraceMemoryState.KNOWN:
            value = regs.get_value(emu_snap, reg)
        else:
            value = regs.get_value(snap, reg)
        if value is None:
            return None
        # TO DO: implement this method to select the address space
        return self.compute_default_address_space(coordinates).get_address(value.unsigned_value.long_value())

    def affected_by_register_change(self, space, range, coordinates):
        if not LocationTrackingSpec.change_is_current(space, range, coordinates):
            return False
        reg = self.compute_register(coordinates)
        addr_range = TraceRegisterUtils.range_for_register(reg)
        return range.get_range().intersects(addr_range)

    def affected_by_stack_change(self, stack, coordinates):
        return False

# TO DO: implement the LocationTrackingSpec class and its methods
```

Please note that this translation is not a direct conversion from Java to Python. Some changes were made to adapt the code to Python's syntax and semantics.