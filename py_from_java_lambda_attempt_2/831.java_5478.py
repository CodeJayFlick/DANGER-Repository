Here is a translation of the Java code into equivalent Python code:

```Python
class DbgModelTargetThreadImpl:
    SUPPORTED_KINDS = {"ADVANCE", "FINISH", "LINE", "OVER", "OVER_LINE", "RETURN", "UNTIL", "EXTENDED"}

    def __init__(self, threads: 'DbgModelTargetThreadContainer', process: 'DbgModelTargetProcess', thread: 'DbgThread'):
        self.thread = thread
        self.process = process
        self.registers = DbgModelTargetRegisterContainerImpl(self)
        self.stack = DbgModelTargetStackImpl(self, process)

    def get_display(self):
        if self.get_manager().is_kernel_mode():
            return f"[PR {self.thread.id}]"
        tidstr = str(self.thread.tid, 16)
        if self.base == 16:
            tidstr = "0x" + tidstr
        return f"[{self.thread.id}:{tidstr}]"

    def thread_selected(self, event_thread: 'DbgThread', frame: 'DbgStackFrame', cause: 'DbgCause'):
        if event_thread.equals(self.thread):
            focus_scope = DbgModelTargetFocusScope()
            focus_scope.set_focus(self)

    def thread_state_changed_specific(self, state: 'DbgState', reason: 'DbgReason'):
        target_state = self.convert_state(state)
        execution_type = self.thread.executing_processor_type.description
        attributes = {"STATE_ATTRIBUTE_NAME": target_state, "ARCH_ATTRIBUTE_NAME": execution_type}
        self.change_attributes({}, {}, attributes, reason.desc())
        self.registers.thread_state_changed_specific(state, reason)
        self.stack.thread_state_changed_specific(state, reason)

    def step(self, kind: 'TargetStepKind'):
        if kind == TargetStepKind.SKIP:
            raise UnsupportedOperationException(kind.name())
        elif kind == TargetStepKind.ADVANCE:
            return CompletableFuture.runnable(lambda: self.thread.console("advance"))
        else:
            return model.gate_future(self.thread.step(self.convert_to_dbg(kind)))

    def step(self, args: dict):
        return model.gate_future(self.thread.step(args))

    def set_active(self):
        manager = self.get_manager()
        command = DbgSetActiveThreadCommand(manager, self.thread, None)
        return manager.execute(command)

    @property
    def registers(self) -> 'DbgModelTargetRegisterContainerAndBank':
        return self._registers

    @property
    def stack(self) -> 'DbgModelTargetStackImpl':
        return self._stack

    @property
    def thread(self) -> 'DbgThread':
        return self._thread

    @property
    def process(self) -> 'DbgModelTargetProcess':
        return self._process

    def is_accessible(self):
        return accessible

    def get_executing_processor_type(self):
        return self.thread.executing_processor_type.description

    def set_base(self, value: int):
        self.base = value
        attributes = {"DISPLAY_ATTRIBUTE_NAME": self.get_display()}
        self.change_attributes({}, {}, attributes, "Started")
```

Please note that this is a direct translation of the Java code into Python. The equivalent Python classes and methods are not exactly identical to their Java counterparts due to differences in syntax and semantics between the two languages.