class LogicalBreakpointRow:
    def __init__(self, provider: 'DebuggerBreakpointsProvider', lb: 'LogicalBreakpoint'):
        self.provider = provider
        self.lb = lb

    def __str__(self):
        return f"<Row {self.lb}>"

    @property
    def logical_breakpoint(self):
        return self.lb

    @property
    def enablement(self):
        if self.provider.is_filter_by_current_trace() and self.provider.current_trace is not None:
            return self.lb.compute_enablement_for_trace(self.provider.current_trace)
        else:
            return self.lb.compute_enablement()

    def set_enablement(self, en: 'Enablement'):
        assert en.consistent and en.effective
        self.set_enabled(en.enabled)

    @property
    def is_enabled(self):
        enablement = self.enablement
        if not enablement.consistent:
            return None
        return enablement.enabled and enablement.effective

    def set_enabled(self, enabled: bool):
        if enabled:
            future = self.provider.is_filter_by_current_trace() \
                and self.lb.enable_for_trace(self.provider.current_trace) or \
                self.lb.enable()
            future.exceptionally(lambda ex: self.provider.breakpoint_error("Toggle Breakpoint", "Could not enable breakpoint", ex))
        else:
            future = self.provider.is_filter_by_current_trace() \
                and self.lb.disable_for_trace(self.provider.current_trace) or \
                self.lb.disable()
            future.exceptionally(lambda ex: self.provider.breakpoint_error("Toggle Breakpoint", "Could not disable breakpoint", ex))

    @property
    def image_name(self):
        program = self.lb.get_program()
        if program is None:
            return ""
        domain_file = program.get_domain_file()
        if domain_file is None:
            return program.name
        return domain_file.name

    @property
    def address(self):
        return self.lb.get_address()

    @property
    def length(self):
        return self.lb.get_length()

    @property
    def domain_object(self):
        return self.lb.get_domain_object()

    @property
    def kinds(self):
        return TraceBreakpointKindSet.encode(self.lb.get_kinds())

    def get_location_count(self):
        if self.provider.is_filter_by_current_trace():
            return len(self.lb.get_trace_breakpoints(self.provider.current_trace))
        else:
            return len(self.lb.get_trace_breakpoints())

    def is_mapped(self):
        if self.provider.is_filter_by_current_trace():
            return self.lb.get_mapped_traces().contains(self.provider.current_trace)
        else:
            return not self.lb.get_mapped_traces().empty
