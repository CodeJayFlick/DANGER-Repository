class LldbModelTargetStackFrameRegisterContainerImpl:
    def __init__(self, frame):
        self.frame = frame
        super().__init__(frame.get_model(), frame, "Registers", "StackFrameRegisterContainer")
        self.request_attributes(True)

    @property
    def name(self):
        return "Registers"

    async def request_attributes(self, refresh=False):
        banks = await self.manager.list_stack_frame_register_banks(self.frame.get_frame())
        target_banks = [self.get_target_register_bank(val) for val in banks.values()]
        await self.change_attributes([], target_banks, {}, "Refreshed")

    @property
    async def manager(self):
        return self.frame.get_manager()

    async def get_target_register_bank(self, val):
        if isinstance(val, SBValue):
            target_object = self.get_map_object(val)
            if target_object:
                target_bank = LldbModelTargetObject(target_object)
                target_bank.set_model_object(val)
                return target_bank
            else:
                return LlbDModelTargetStackFrameRegisterBankImpl(self, val)

    async def thread_state_changed_specific(self, state: StateType, reason: LldbReason):
        if state == StateType.eStateStopped:
            await self.request_attributes(False)
            for attribute in self.get_cached_attributes().values():
                if isinstance(attribute, LlbDModelTargetRegisterBank):
                    bank = attribute
                    bank.thread_state_changed_specific(state, reason)

class SBValue:
    pass

class StateType:
    eStateStopped = None

class LldbReason:
    pass

class LlbDModelTargetObject:
    def __init__(self, target_object):
        self.target_object = target_object

    @property
    def model_object(self):
        return self.target_object

    def set_model_object(self, val):
        self.model_object = val

class LlbDModelTargetStackFrameRegisterBankImpl(LlbDModelTargetObject):
    pass

class LlbDModelTargetRegisterBank:
    def thread_state_changed_specific(self, state: StateType, reason: LldbReason):
        pass
