class DebugEventInformation:
    def __init__(self, type: int, pid: int, tid: int):
        self.type = type
        self.pid = ProcessId(pid)
        self.tid = ThreadId(tid)

    @property
    def type(self) -> int:
        return self.type

    @property
    def session_id(self) -> 'SessionId':
        return self.sid

    @property
    def process_id(self) -> 'ProcessId':
        return self.pid

    @property
    def thread_id(self) -> 'ThreadId':
        return self.tid

    def set_thread(self, tid: 'ThreadId'):
        self.tid = tid

    def set_process(self, pid: 'ProcessId'):
        self.pid = pid

    def set_session(self, sid: 'SessionId'):
        self.sid = sid

    @property
    def executing_processor_type(self) -> int:
        return self.executing_processor_type

    @executing_processor_type.setter
    def set_executing_processor_type(self, exec_type: int):
        self.executing_processor_type = exec_type


class ProcessId(int):
    pass


class ThreadId(int):
    pass


class SessionId(int):
    pass
