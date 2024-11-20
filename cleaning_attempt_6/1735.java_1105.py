class LldbModelTargetThreadContainerImpl:
    def __init__(self, process):
        self.process = process
        super().__init__(process.model, process, "Threads", "ThreadContainer")
        self.change_attributes([], {"Base": 16}, "Initialized")

        manager().add_events_listener(self)
        request_elements(False)

    @property
    def base(self):
        return self._base

    @base.setter
    def base(self, value):
        if isinstance(value, int):
            self._change_attributes([], {"Base": value}, "Modified")
            for child in get_cached_elements().values():
                if isinstance(child, LldbModelTargetThreadImpl):
                    target_thread = child
                    target_thread.base = value
        else:
            raise DebuggerIllegalArgumentException("Base should be numeric")

    def thread_created(self, thread):
        self._change_elements([], [get_target_thread(thread)], {}, "Created")
        target_thread = get_target_thread(thread)
        target_thread.thread_state_changed_specific(StateType.eStateConnected,
                                                     LldbReason.get_reason(None))
        listeners().fire_event(proxy(), target_thread, TargetEventType.THREAD_CREATED,
                                 f"Thread {DebugClient.id(thread)} started", [target_thread])

    def thread_replaced(self, thread):
        self._change_elements([], [get_target_thread(thread)], {}, "Created")
        target_thread = get_target_thread(thread)
        self._change_elements([], [target_thread], {}, "Created")

    def thread_state_changed(self, thread, state, cause, reason):
        target_thread = get_target_thread(thread)
        event_type = get_event_type(state, cause, reason)
        listeners().fire_event(proxy(), target_thread, event_type,
                                 f"Thread {DebugClient.id(thread)} state changed", [target_thread])
        target_thread.thread_state_changed_specific(state, reason)

    def thread_exited(self, thread):
        thread_id = LldbModelTargetThreadImpl.index_thread(thread)
        target_thread = get_map_object(thread)
        if target_thread is not None:
            listeners().fire_event(proxy(), target_thread, TargetEventType.THREAD_EXITED,
                                     f"Thread {thread_id} exited", [target_thread])
        self._change_elements([thread_id], [], {}, "Exited")

    def request_elements(self, refresh):
        return manager().list_threads(process).then_accept(lambda by_tid:
            threads = list(map(get_target_thread, by_tid.values()))
            set_elements(threads, {"": None}, "Refreshed"))

    @property
    def proxy(self):
        pass

    @property
    def listeners(self):
        pass

    @property
    def manager(self):
        pass

    @staticmethod
    def get_event_type(state, cause, reason):
        if state.swig_value() == 0:
            return TargetEventType.RUNNING
        elif state.swig_value() in [1, 2, 3, 4]:
            return TargetEventType.PROCESS_CREATED
        elif state.swig_value() in [5, 6, 7]:
            return TargetEventType.RUNNING
        elif state.swig_value() in [8, 9, 10]:
            return TargetEventType.PROCESS_EXITED
        else:
            return TargetEventType.STOPPED

    def get_target_thread(self, thread):
        target_object = get_map_object(thread)
        if target_object is not None:
            target_thread = target_object
            target_thread.model_object = thread
            return target_thread
        return LldbModelTargetThreadImpl(self, process, thread)

    @property
    def parent(self):
        pass

    def write_configuration_option(self, key, value):
        if key == "Base":
            self._change_attributes([], {"Base": value}, "Modified")
            for child in get_cached_elements().values():
                if isinstance(child, LldbModelTargetThreadImpl):
                    target_thread = child
                    target_thread.base = value
        else:
            raise DebuggerIllegalArgumentException("Base should be numeric")

    @property
    def cached_elements(self):
        pass

class TargetEventType(Enum):
    RUNNING = 0
    PROCESS_CREATED = 1
    STOPPED = 2
    PROCESS_EXITED = 3
