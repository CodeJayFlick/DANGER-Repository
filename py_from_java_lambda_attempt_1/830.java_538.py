Here is the translation of the given Java code into equivalent Python:

```Python
class DbgModelTargetThreadContainerImpl:
    def __init__(self, process):
        self.process = process
        super().__init__(process.model, "Threads", "ThreadContainer")
        self.change_attributes([], {"BASE_ATTRIBUTE_NAME": 16}, "Initialized")

        manager.add_events_listener(self)
        request_elements(False)

    def thread_created(self, thread):
        change_elements([], [get_target_thread(thread)], {}, "Created")
        target_thread = get_target_thread(thread)
        change_elements([], [target_thread], {}, "Created")
        target_thread.thread_state_changed_specific(DbgState.STARTING, DbgReason.get_reason(None))
        listeners.fire_event(get_proxy(), target_thread, TargetEventType.THREAD_CREATED,
                              f"Thread {thread.id} started", [target_thread])

    def thread_state_changed(self, thread, state, cause, reason):
        target_thread = get_target_thread(thread)
        event_type = get_event_type(state, cause, reason)
        listeners.fire_event(get_proxy(), target_thread, event_type,
                              f"Thread {thread.id} state changed", [target_thread])
        target_thread.thread_state_changed_specific(state, reason)

    def thread_exited(self, thread_id):
        model_impl = self.model
        target_thread = model_impl.get_model_object(thread_id)
        if target_thread is not None:
            listeners.fire_event(get_proxy(), target_thread, TargetEventType.THREAD_EXITED,
                                  f"Thread {thread_id} exited", [target_thread])
        change_elements([DbgModelTargetThreadImpl.index_thread(thread_id)], [], {}, "Exited")

    def get_event_type(self, state, cause, reason):
        if state == DbgState.RUNNING:
            return TargetEventType.RUNNING
        elif state in (DbgState.STOPPED, DbgState.EXIT):
            if isinstance(reason, DbgEndSteppingRangeReason):
                return TargetEventType.STEP_COMPLETED
            elif isinstance(reason, DbgSignalReceivedReason):
                return TargetEventType.SIGNAL
            elif isinstance(reason, DbgExitedReason):
                return TargetEventType.EXCEPTION
            elif isinstance(reason, DbgExitNormallyReason):
                return TargetEventType.THREAD_EXITED
        return TargetEventType.STOPPED

    def request_elements(self, refresh):
        process.list_threads().then_accept(by_tid =>
            threads = [self.get_target_thread(tid) for tid in by_tid.values()]
            self.set_elements(threads, {}, "Refreshed")
        )

    def get_target_thread(self, thread):
        model_impl = self.model
        model_object = model_impl.get_model_object(thread)
        if model_object is not None:
            return model_object
        else:
            return DbgModelTargetThreadImpl(self, process, thread)

    def write_configuration_option(self, key, value):
        if key == "BASE_ATTRIBUTE_NAME":
            if isinstance(value, int):
                self.change_attributes([], {"BASE_ATTRIBUTE_NAME": value}, "Modified")
                for child in self.get_cached_elements().values():
                    if isinstance(child, DbgModelTargetThreadImpl):
                        target_thread = child
                        target_thread.set_base(value)
        else:
            raise DebuggerIllegalArgumentException("Base should be numeric")

    return CompletableFuture.NIL

class TargetEventType(Enum):
    RUNNING = 1
    STOPPED = 2
    STEP_COMPLETED = 3
    SIGNAL = 4
    EXCEPTION = 5
    THREAD_EXITED = 6

DbgState = Enum('STARTING', 'RUNNING', 'STOPPED', 'EXIT')
```

Note that this is a direct translation of the given Java code into equivalent Python, without considering any specific requirements or constraints.