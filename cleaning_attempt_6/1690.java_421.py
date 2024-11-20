class RegisterContainerInterface:
    def __init__(self):
        self.attributes = {
            "General Purpose Registers": {"type": LldbModelTargetStackFrameRegisterBank},
            "Exception State Registers": {"type": LlldbModelTargetStackFrameRegisterBank, "required": True},
            "Floating Point Registers": {"type": LlbddModelTargetStackFrameRegisterBank, "required": True}
        }

    def get_target_register_bank(self, val):
        # Note: SBValue is not a standard Python type. You would need to define it or replace with something similar.
        return None

class LldbModelTargetObject:
    pass

class LlbddModelTargetStackFrameRegisterBank:
    pass
