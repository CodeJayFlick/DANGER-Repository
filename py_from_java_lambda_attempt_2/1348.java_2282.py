Here is the translation of the given Java code into equivalent Python:

```Python
class GdbInsertBreakpointCommand:
    def __init__(self, manager, thread_id, location, breakpoint_type):
        self.manager = manager
        self.thread_id = thread_id
        self.location = location
        self.breakpoint_type = breakpoint_type

    def make_thread_part(self):
        if self.thread_id is None:
            return ""
        else:
            return f"-p {self.thread_id}"

    @staticmethod
    def escape(param):
        import re
        pattern = r"([.*+?^${}()|[\]\\])"
        escaped_param = re.sub(pattern, lambda x: "\\" + x.group(), param)
        return f"'{escaped_param}'"

    def encode(self, thread_part):
        if self.breakpoint_type == "BREAKPOINT":
            return f"-break-insert {thread_part} {self.escape(self.location)}"
        elif self.breakpoint_type == "HW_BREAKPOINT":
            return f"-break-insert -h {thread_part} {self.escape(self.location)}"
        elif self.breakpoint_type == "DPRINTF":
            return f"-dprintf-insert {thread_part} {self.escape(self.location)}"
        elif self.breakpoint_type in ["HW_WATCHPOINT", "READ_WATCHPOINT", "ACCESS_WATCHPOINT"]:
            cmd = f"watch -l {self.location}"  # escaping here causes GDB to treat as literal???
            return f"-interpreter-exec {thread_part} console {self.escape(cmd)}"
        else:
            raise ValueError(f"type={self.breakpoint_type}")

    def handle(self, event, pending):
        if super().handle(event, pending):
            return True
        elif isinstance(event, GdbBreakpointCreatedEvent):
            pending.claim(event)
            return False

    def complete(self, pending):
        done = pending.check_completion(GdbCommandDoneEvent)
        if self.breakpoint_type in ["HW_WATCHPOINT", "READ_WATCHPOINT", "ACCESS_WATCHPOINT"]:
            evt = pending.find_single_of(GdbBreakpointCreatedEvent)
            return evt.get_breakpoint_info()
        bkpt = GdbBreakpointInfo.parse(done.info, self.manager.current_inferior().id)
        # GDB does not give notification for breakpoints added by GDB/MI commands
        self.manager.do_breakpoint_created(bkpt, pending)
        return bkpt

class AbstractGdbCommandWithThreadId:
    def __init__(self, manager, thread_id):
        self.manager = manager
        self.thread_id = thread_id

    @abstractmethod
    def handle(self, event, pending):
        pass

    @abstractmethod
    def complete(self, pending):
        pass

# Assuming GdbEvent and GdbPendingCommand are defined elsewhere in the code.
```

Please note that this translation is not a direct conversion from Java to Python. It's more of an equivalent implementation in Python. The original Java code may have some specific requirements or constraints which might be different when translated into Python, so you should adjust it according to your needs and environment.