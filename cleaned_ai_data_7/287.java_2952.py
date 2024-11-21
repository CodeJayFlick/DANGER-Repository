class TraceEventListener:
    def __init__(self):
        self.recorder = None
        self.target = None
        self.trace = None
        self.memory_manager = None
        self.valid = True
        self.reorderer = DebuggerCallbackReorderer(self)
        self.queue = PrivatelyQueuedListener(DebuggerModelListener)

    def init(self, collection):
        super().__init__()
        self.recorder = collection.get_recorder()
        self.target = self.recorder.get_target()
        self.trace = self.recorder.get_trace()
        self.memory_manager = self.trace.get_memory_manager()

    def event(self, object, thread, type, description, parameters):
        if not self.valid:
            return
        print(f"Event: {type} thread={thread} description={description} params={parameters}")
        # Just use this to step the snaps. Creation/destruction still handled in add/remove
        if thread is None and type != TargetEventType.PROCESS_CREATED:
            print("Null eventThread for", type)
            return

    def successor(self, ref):
        return PathUtils.is_ancestor(self.target.get_path(), ref.get_path())

    def any_ref(self, parameters):
        for p in parameters:
            if isinstance(p, TargetObject):
                return True
        return False

    def any_successor(self, parameters):
        for p in parameters:
            if isinstance(p, TargetObject) and not self.successor((TargetObject)p):
                continue
            return True
        return False

    def event_applies(self, thread, type, parameters):
        if thread is not None:
            return self.successor(thread)
        if any_ref(parameters):
            return any_successor(parameters)
        return True  # Some session-wide event, I suppose

    def execution_state_changed(self, stateful, state):
        if not self.valid:
            return
        print(f"State {state} for {stateful}")
        target = self.recorder.get_object_manager().find_thread_or_process(stateful)
        if target is not None and target == self.target and state == TargetExecutionState.TERMINATED:
            self.recorder.stop_recording()
            return

    def invalidate_cache_requested(self, object):
        if not self.valid or self.ignore_invalidation:
            return
        if isinstance(object, TargetRegisterBank):
            rec = self.recorder.get_thread_recorder_for_successor(object)
            if rec is not None:
                rec.invalidate_register_values((TargetRegisterBank)object)

    def registers_updated(self, bank, updates):
        if not self.valid:
            return
        rec = self.recorder.get_thread_recorder_for_successor(bank)
        if rec is not None:
            rec.record_register_values((TargetRegisterBank)bank, updates)

    def memory_updated(self, memory, address, data):
        if not self.valid:
            return
        snap = self.recorder.get_snap()
        print(f"Memory updated: {address} ({len(data)})")
        path = memory.get_joined_path(".")
        self.recorder.par_tx.execute("Memory observed:", lambda: self.memory_manager.put_bytes(snap, address, ByteBuffer.wrap(data)), path)

    def dispose(self):
        self.target.get_model().remove_model_listener(self.reorderer)
        self.reorderer.dispose()

class DebuggerCallbackReorderer:
    def __init__(self, listener):
        self.listener = listener

    def reorder(self):
        pass  # Reordering not implemented in Python equivalent.

class PrivatelyQueuedListener:
    def __init__(self, type_class):
        self.type_class = type_class
