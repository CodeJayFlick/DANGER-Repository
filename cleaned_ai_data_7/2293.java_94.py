class AbstractDebuggerModelTest:
    def __init__(self):
        self.m = None
        self.dummy = None

    def seed_path(self) -> list[str]:
        return []

    def find_active_scope(self) -> dict | None:
        if not isinstance(self.m, dict):
            raise TypeError("m must be a dictionary")
        try:
            return self.m.get(TargetActiveScope)
        except KeyError:
            pass
        return None

    # ... (similar methods for other classes)

    @staticmethod
    def validate_completion_thread():
        m.validate_completion_thread()

    @classmethod
    def setUpDebuggerModelTest(cls):
        cls.m = model_host()
        cls.dummy = dummy_proc()

    @classmethod
    def tearDownDebuggerModelTest(cls):
        if cls.m is not None:
            cls.m.close()
        if cls.dummy is not None:
            cls.dummy.close()

class DebuggerTestSpecimen:
    def run_dummy(self) -> DummyProc | None:
        pass

    def get_launcher_args(self) -> dict[str, object]:
        return {}

    def get_launch_script(self) -> list[str]:
        return []

    @staticmethod
    def is_running_in(process: TargetProcess, test: AbstractDebuggerModelTest):
        # ... (implementation)
        pass

class DebuggerModelListener:
    async def event(
            self,
            obj: object | None,
            thread: TargetThread | None,
            type: str,
            description: str,
            parameters: list[object] | None
    ):
        print(f"EVENT {type} '{description}'")

    @staticmethod
    async def breakpoint_hit(container: TargetObject, trapped: TargetObject, frame: TargetStackFrame):
        pass

class DummyProc:
    # ... (implementation)
    pass

def trap_at(bp_expression: str, target_object: object) -> TargetObject | None:
    listener = DebuggerModelListener()
    try:
        target_object.getModel().addModelListener(listener)

        breakpoints = find_breakpoint_spec_container(target_object.getPath())
        wait_on(breakpoints.placeBreakpoint(bp_expression, {TargetBreakpointKind.SOFTWARE_EXECUTE}))

        state = AsyncState(
            m.suitable(TargetExecutionStateful.class, target_object.getPath()))
        while not listener.trapped.done():
            resume(target_object)
            execution_state = await state.waitUntil(lambda s: s != TargetExecutionState.RUNNING)
            assert isinstance(execution_state, TargetExecutionState) and execution_state.isAlive()
    finally:
        target_object.getModel().removeModelListener(listener)

def run_test_detach(specimen: DebuggerTestSpecimen):
    process = retry_for_process_running(specimen, this)
    detachable = m.suitable(TargetDetachable.class, process.getPath())
    wait_acc(detachable)
    await detachable.detach()
    assert not DebugModelConventions.isProcessAlive(process), "Target terminated before it was trapped"

def run_test_kill(specimen: DebuggerTestSpecimen):
    process = retry_for_process_running(specimen, this)
    killable = m.suitable(TargetKillable.class, process.getPath())
    wait_acc(killable)
    await killable.kill()
    assert not DebugModelConventions.isProcessAlive(process), "Target terminated before it was trapped"

def run_test_resume_terminates(specimen: DebuggerTestSpecimen):
    process = retry_for_process_running(specimen, this)
    resumable = m.suitable(TargetResumable.class, process.getPath())
    state = AsyncState(
        m.suitable(TargetExecutionStateful.class, process.getPath()))
    execution_state = await state.waitUntil(lambda s: s != TargetExecutionState.RUNNING)
    assert isinstance(execution_state, TargetExecutionState) and execution_state.isAlive()
    await resumable.resume()
    assert not DebugModelConventions.isProcessAlive(process), "Target terminated before it was trapped"

def run_test_resume_interrupt_many(specimen: DebuggerTestSpecimen):
    process = retry_for_process_running(specimen, this)
    resumable = m.suitable(TargetResumable.class, process.getPath())
    interruptible = m.suitable(TargetInterruptible.class, process.getPath())
    for _ in range(repetitions):
        wait_acc(resumable)
        await resumable.resume()
        if stateful is not None:
            assert isinstance(stateful.getExecutionState(), TargetExecutionState) and stateful.getExecutionState() == TargetExecutionState.RUNNING
        # NB. Never have to waitAcc to interrupt. It's likely inaccessible, anyway.
        await interruptible.interrupt()
        if stateful is not None:
            assert isinstance(stateful.getExecutionState(), TargetExecutionState) and stateful.getExecutionState() == TargetExecutionState.STOPPED

    await m.getModel().ping("Are you still there?")
