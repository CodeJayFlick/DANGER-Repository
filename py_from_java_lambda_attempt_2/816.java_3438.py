Here is the translation of the Java code into Python:

```Python
class DbgModelTargetProcessContainerImpl:
    def __init__(self, session):
        super().__init__()
        self.session = session
        self.change_attributes([], {"BASE_ATTRIBUTE_NAME": 16}, "Initialized")
        self.manager.add_events_listener(self)

    def process_added(self, proc, cause):
        if isinstance(proc, DbgProcess) and isinstance(cause, DbgCause):
            session = self.get_parent()
            session.set_accessible(True)
            target_process = self.get_target_process(proc)
            self.change_elements([], [target_process], {}, "Added")
            target_process.process_started(proc.pid)
            listeners = self.get_listeners()
            event_type = TargetEventType.PROCESS_CREATED
            message = f"Process {proc.id} started {target_process.name} pid={proc.pid}"
            listeners.fire_event(self, None, event_type, message, [target_process])

    def process_started(self, proc, cause):
        if isinstance(proc, DbgProcess) and isinstance(cause, DbgCause):
            target_process = self.get_target_process(proc)
            target_process.process_started(proc.pid)

    def process_removed(self, process_id, cause):
        if isinstance(process_id, DebugProcessId) and isinstance(cause, DbgCause):
            change_elements([DbgModelTargetProcessImpl.index_process(process_id)], [], {}, "Removed")

    def thread_created(self, thread, cause):
        if isinstance(thread, DbgThread) and isinstance(cause, DbgCause):
            target_process = self.get_target_process(thread.process)
            target_process.threads.thread_created(thread)

    def thread_state_changed(self, thread, state, cause, reason):
        if isinstance(thread, DbgThread) and isinstance(state, DbgState) and isinstance(cause, DbgCause) and isinstance(reason, DbgReason):
            target_process = self.get_target_process(thread.process)
            target_process.thread_state_changed_specific(thread, state)

    def thread_exited(self, thread_id, proc, cause):
        if isinstance(thread_id, DebugThreadId) and isinstance(proc, DbgProcess) and isinstance(cause, DbgCause):
            target_process = self.get_target_process(proc)
            if target_process is not None:
                target_process.threads.thread_exit(thread_id)

    def module_loaded(self, proc, info, cause):
        if isinstance(proc, DbgProcess) and isinstance(info, DebugModuleInfo) and isinstance(cause, DbgCause):
            target_process = self.get_target_process(proc)
            modules = target_process.modules
            memory = target_process.memory

    def module_unloaded(self, proc, info, cause):
        if isinstance(proc, DbgProcess) and isinstance(info, DebugModuleInfo) and isinstance(cause, DbgCause):
            target_process = self.get_target_process(proc)
            target_process.modules.library_unload(info.toString())
            memory = target_process.memory
            if memory is not None:
                memory.request_elements(False)

    def request_elements(self, refresh):
        return CompletableFuture.runAsync(lambda: 
            processes = list(map(self.get_target_process, by_iid.values()))
            self.set_elements(processes, {}, "Refreshed")
        )

    def get_target_process(self, id):
        if isinstance(id, DebugProcessId):
            model_impl = DbgModelImpl()
            model_object = model_impl.model_object(id)
            return model_object

    def write_configuration_option(self, key, value):
        if key == 'BASE_ATTRIBUTE_NAME':
            self.change_attributes([], {"BASE_ATTRIBUTE_NAME": value}, "Modified")
```

Please note that this is a direct translation of the Java code into Python. The equivalent Python classes and methods are used to maintain compatibility with the original Java code.