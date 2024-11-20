class SetFlowOverrideCmd:
    def __init__(self, inst_addr=None, set_view=None, flow_override=None):
        self.inst_addr = inst_addr
        self.set_view = set_view
        self.flow_override = flow_override

    @property
    def description(self):
        if self.set_view is not None and self.flow_override is not None:
            return f"Set Flow Override for all instructions in {self.set_view} with type {self.flow_override}"
        elif self.inst_addr is not None and self.flow_override is not None:
            return f"Set Flow Override for instruction at address {self.inst_addr} to {self.flow_override}"
        else:
            raise ValueError("Invalid command parameters")

    def apply_to(self, program):
        if self.set_view is not None:
            monitor = TaskMonitor()
            monitor.initialize(len(program.get_listing().get_address_ranges()))
            for instr in program.get_listing().get_instructions(self.set_view, True):
                if monitor.is_cancelled():
                    break
                instr.set_flow_override(self.flow_override)
                monitor.set_progress(monitor.progress + 1)

        elif self.inst_addr is not None:
            instr = program.get_listing().get_instruction_at(self.inst_addr)
            if instr is None:
                return False

            if instr.get_flow_override() == self.flow_override:
                return True
            else:
                instr.set_flow_override(self.flow_override)
                return True

        raise ValueError("Invalid command parameters")
