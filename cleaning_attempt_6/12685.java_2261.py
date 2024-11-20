class FlowType:
    def __init__(self):
        self.has_fall = False
        self.is_call = False
        self.is_jump = False
        self.is_terminal = False
        self.is_computed = False
        self.is_conditional = False
        self.is_override = False

    @property
    def has_fallthrough(self):
        return self.has_fall

    @property
    def is_call_(self):
        return self.is_call

    @property
    def is_computed_(self):
        return self.is_computed

    @property
    def is_conditional_(self):
        return self.is_conditional

    @property
    def is_flow(self):
        return True

    @property
    def is_jump_(self):
        return self.is_jump

    @property
    def is_terminal_(self):
        return self.is_terminal

    @property
    def is_unconditional_(self):
        return not self.is_conditional_

    @property
    def is_override_(self):
        return self.is_override


class FlowTypeBuilder:
    def __init__(self, type, name):
        self.type = type
        self.name = name

    def set_has_fall(self):
        self.has_fall = True
        return self

    def set_is_call(self):
        self.is_call = True
        return self

    def set_is_jump(self):
        self.is_jump = True
        return self

    def set_is_terminal(self):
        self.is_terminal = True
        return self

    def set_is_computed(self):
        self.is_computed = True
        return self

    def set_is_conditional(self):
        self.is_conditional = True
        return self

    def set_is_override(self):
        self.is_override = True
        return self

    def build(self):
        flow_type = FlowType()
        flow_type.has_fall = self.has_fall
        flow_type.is_call = self.is_call
        flow_type.is_jump = self.is_jump
        flow_type.is_terminal = self.is_terminal
        flow_type.is_computed = self.is_computed
        flow_type.is_conditional = self.is_conditional
        flow_type.is_override = self.is_override
        return flow_type


# Example usage:
builder = FlowTypeBuilder(0, "Flow Type")
flow_type = builder.set_is_call().set_is_jump().build()
print(flow_type.has_fallthrough)  # False
print(flow_type.is_call_)          # True
print(flow_type.is_computed_)      # False (default)
# ...
