class ClearFallThroughCmd:
    def __init__(self, inst_addr):
        self.inst_addr = inst_addr

    def apply_to(self, obj):
        program = Program(obj)
        instruction = program.get_listing().get_instruction_at(inst_addr)
        instruction.clear_fall_through_override()
        return True


def get_name():
    return "Clear Fall-through Override"


def get_status_msg():
    return None
