class LldbModelTargetAvailable:
    PID_ATTRIBUTE_NAME = "pid"

    def get_pid(self):
        pass  # TODO: implement this method

    def set_base(self, value):
        pass  # TODO: implement this method


from ghidra.dbg.target import TargetAttachable

LldbModelTargetAvailable = type('LldbModelTargetAvailable', (object,), {
    '__module__': 'agent.llldb.model.iface2',
    'PID_ATTRIBUTE_NAME': "pid",
    **asdict(TargetAttachable)
})
