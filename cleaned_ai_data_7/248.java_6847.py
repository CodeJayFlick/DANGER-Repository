class DebuggerTracePcodeEmulator:
    def __init__(self, tool: 'PluginTool', trace: ' Trace', snap: int, recorder: 'TraceRecorder'):
        super().__init__(trace, snap)
        self.tool = tool
        self.recorder = recorder

    def is_register_known(self, thread_name: str, register: 'Register') -> bool:
        thread = next((t for t in trace.get_thread_manager().get_live_threads() if t.path == thread_name), None)
        space = trace.get_memory_manager().get_memory_register_space(thread, False)
        return space.state(snap, register) == TraceMemoryState.KNOWN

    def create_thread(self, name: str):
        thread = super().create_thread(name)
        context_reg = language.get_context_base_register()
        if context_reg != Register.NO_CONTEXT and not self.is_register_known(name, context_reg):
            context = trace.get_register_context_manager().get_value_with_default(language, context_reg, snap, thread.counter)
            thread.override_context(context)
        return thread

    def create_shared_state(self) -> 'PcodeExecutorState[bytes]':
        return ReadsTargetMemoryPcodeExecutorState(self.tool, self.trace, self.snap, None, 0, self.recorder)

    def create_local_state(self, emu_thread: 'BytesPcodeThread') -> 'PcodeExecutorState[bytes]':
        trace_thread = next((t for t in self.trace.get_thread_manager().get_live_threads() if t.path == emu_thread.name), None)
        return ReadsTargetRegistersPcodeExecutorState(self.tool, self.trace, self.snap, trace_thread, 0, self.recorder)

class PluginTool:
    pass

class TraceRecorder:
    pass

class Register:
    NO_CONTEXT = ...

class PcodeThread(bytes):
    def override_context(self, context: 'RegisterValue'):
        ...
