class RISCVEmulateInstructionStateModifier:
    def __init__(self, emu):
        pass  # equivalent to super(emu)

    def initial_execute_callback(self, emulate, current_address, context_register_value):
        raise LowlevelError()  # no default implementation

    def post_execute_callback(self, emulate, last_execute_address,
                               last_execute_pcode=None, last_pcode_index=-1, current_address=None):
        raise LowlevelError()  # no default implementation


class Emulate:
    pass


class Address:
    pass


class RegisterValue:
    pass


class PcodeOp:
    pass


class LowlevelError(Exception):
    pass
