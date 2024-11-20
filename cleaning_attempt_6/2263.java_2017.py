class TestTargetSession:
    def __init__(self, model: 'TestDebuggerObjectModel', root_hint: str):
        self.environment = TestTargetEnvironment(self)
        self.processes = TestTargetProcessContainer(self)
        self.interpreter = TestTargetInterpreter(self)
        self.mimick_java_launcher = TestMimickJavaLauncher(self)

    def add_process(self, pid: int) -> 'TestTargetProcess':
        return self.processes.add_process(pid)

    @property
    def model(self):
        return super().getModel()

    async def request_focus(self, obj: 'TargetObject'):
        await self.model.request_focus(obj)

    def simulate_step(self, event_thread: 'TestTargetThread'):
        event_thread.set_state(TargetExecutionState.RUNNING)
        listeners.fire_event(self, event_thread, TargetEventType.STEP_COMPLETED,
                              "Test thread completed a step", [])

        event_thread.set_state(TargetExecutionState.STOPPED)

    async def launch(self, args: dict):
        # TODO: Record the request and allow tests to complete it?
        return await AsyncUtils.NIL

class TestDebuggerObjectModel:
    pass
