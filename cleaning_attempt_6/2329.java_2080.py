class TracePcodeEmulator:
    def __init__(self, trace: 'ghidra.trace.model.Trace', snap: int):
        self._trace = trace
        self._snap = snap

    @staticmethod
    def assert_sleigh(language) -> SleighLanguage:
        if not isinstance(language, SleighLanguage):
            raise ValueError("Emulation requires a sleigh language")
        return language

class TracePcodeExecutorState:
    def __init__(self, trace: 'ghidra.trace.model.Trace', snap: int, thread: 'ghidra.trace.model.thread.TraceThread'):
        self._trace = trace
        self._snap = snap
        self._thread = thread

def write_down(trace: 'ghidra.trace.model.Trace', dest_snap: int, threads_snap: int):
    ss = TracePcodeExecutorState(_trace, _snap)
    ss.write_cache_down(trace, dest_snap, None, 0)

for emu_thread in trace.threads.values():
    ls = TracePcodeExecutorState(_trace, _snap)
    thread = _thread_manager.get_live_thread_by_path(threads_snap, emu_thread.name)
    if thread is None:
        raise ValueError(f"Given trace does not have thread with name/path '{emu_thread.name}' at snap {dest_snap}")
    ls.write_cache_down(trace, dest_snap, thread, 0)

def create_shared_state():
    return TracePcodeExecutorState(_trace, _snap)

def create_local_state(emu_thread):
    return TracePcodeExecutorState(_thread_manager.get_live_thread_by_path(_snap, emu_thread.name), _snap)
