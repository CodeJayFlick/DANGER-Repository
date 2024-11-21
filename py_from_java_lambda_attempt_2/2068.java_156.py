Here's a translation of your Java code into equivalent Python:

```Python
class JdiModelTargetThread:
    def __init__(self, parent, thread_reference, is_element):
        super().__init__(parent, thread_reference.name(), thread_reference, is_element)
        self.thread = thread_reference
        self.event_manager = thread_reference.virtual_machine().event_request_manager()

        self.stack = JdiModelTargetStack(self)
        self.registers = JdiModelTargetRegisterContainer(self)

    def populate_attributes(self):
        added_attributes = JdiModelTargetAttributesContainer(self, "Attributes")
        attrs = {}
        attrs["is_at_breakpoint"] = thread_reference.is_at_breakpoint()
        attrs["is_collected"] = thread_reference.is_collected()
        attrs["is_suspended"] = thread_reference.is_suspended()

        try:
            attrs["entry_count"] = thread_reference.entry_count()
        except IncompatibleThreadStateException as e:
            pass

        try:
            attrs["frame_count"] = thread_reference.frame_count()
        except IncompatibleThreadStateException as e:
            pass

        attrs["suspend_count"] = thread_reference.suspend_count()

        added_attributes.add_attributes(attrs)

    def request_attributes(self, refresh):
        self.populate_attributes()

        change_attributes(added_attributes, "Initialized")

        if target_vm.vm.can_get_current_contended_monitor():
            try:
                monitor = thread_reference.current_contended_monitor()
                if monitor is not None:
                    current_contended_monitor = JdiModelTargetObjectReference(monitor)
                    change_attributes(current_contended_monitor, "Initialized")
            except IncompatibleThreadStateException as e2:
                pass

        if target_vm.vm.can_get_owned_monitor_info():
            try:
                owned_monitors = JdiModelTargetObjectReferenceContainer(self, "Owned Monitors", thread_reference.owned_monitors())
                if owned_monitors is not None:
                    change_attributes(owned_monitors, "Initialized")
            except IncompatibleThreadStateException as e1:
                pass

        thread_group = thread_reference.thread_group()
        self.thread_group = JdiModelTargetThreadGroupContainer(self, thread_group, False) if thread_group else None
        if thread_group is not None:
            change_attributes(thread_group, "Initialized")

        return CompletableFuture.completed_future(None)

    def init(self):
        async_fence = AsyncFence()
        #async_fence.include(request_attributes(True))
        return async_fence.ready()

    def get_display(self):
        if self.thread is None:
            return super().get_display()

        sb = StringBuilder()
        sb.append(self.thread.name())
        if self.location is not None:
            sb.append(" in ")
            sb.append(self.location)
        top_frame = self.stack.frames_by_level[0]
        if top_frame and top_frame.location is not None:
            sb.append(" in ")
            sb.append(top_frame.location.get_display())

        return str(sb)

    def convert_state(self, state):
        match state:
            case ThreadReference.THREAD_STATUS_RUNNING | ThreadReference.THREAD_STATUS_WAIT:
                return TargetExecutionState.RUNNING if self.thread.is_suspended() else TargetExecutionState.STOPPED
            case ThreadReference.THREAD_STATUS_NOT_STARTED:
                return TargetExecutionState.ALIVE
            default:
                return TargetExecutionState.STOPPED

    def step_complete(self, event, cause):
        if event.thread().equals(self.thread) and event.frame is None:
            self.set_location(event.location)
            change_attributes({"location": self.location}, "Refreshed")
            state_changed(self.thread.status(), JdiReason.Reasons.STEP)

    def breakpoint_hit(self, event, cause):
        if event.thread().equals(self.thread):
            self.set_location(event.location)
            change_attributes({"location": self.location}, "Refreshed")
            state_changed(self.thread.status(), JdiReason.Reasons.BREAKPOINT_HIT)

    # Which of these is actually going to fire, i.e. are separate events generated for subclasses?

    def watchpoint_hit(self, event, cause):
        if event.thread().equals(self.thread):
            self.set_location(event.location)
            change_attributes({"location": self.location}, "Refreshed")
            state_changed(self.thread.status(), JdiReason.Reasons.WATCHPOINT_HIT)

    # Which of these is actually going to fire, i.e. are separate events generated for subclasses?

    def access_watchpoint_hit(self, event, cause):
        if event.thread().equals(self.thread):
            self.set_location(event.location)
            change_attributes({"location": self.location}, "Refreshed")
            state_changed(self.thread.status(), JdiReason.Reasons.ACCESS_WATCHPOINT_HIT)

    # Which of these is actually going to fire, i.e. are separate events generated for subclasses?

    def thread_selected(self, event_thread, frame, cause):
        if event_thread.equals(self.thread) and frame is None:
            ((JdiModelTargetFocusScope) search_for_suitable(TargetFocusScope)).set_focus(self)

    # Which of these is actually going to fire, i.e. are separate events generated for subclasses?

    def state_changed(self, state, reason):
        target_state = self.convert_state(state)
        if target_state == TargetExecutionState.STOPPED:
            update()
            thread_selected(self.thread, None, JdiCause.Causes.UNCLAIMED)

        target_vm.vm.state_changed(target_state, reason)
        event_handler = get_manager().get_event_handler(target_vm.vm)
        event_handler.listeners_event.fire_thread_statechanged(self.thread, state, JdiCause.Causes.UNCLAIMED, reason)

    def thread_state_changed(self, target_state):
        change_attributes({"state": target_state}, "Refreshed")

    # Which of these is actually going to fire, i.e. are separate events generated for subclasses?

    async def update(self):
        await self.registers.update()
        return stack.update().then_accept(lambda __: (change_attributes({"display": get_display()}, "Refreshed"))).exceptionally(ex => {
            print(f"Could not update stack for thread {self}")
            return None
        })

    # Which of these is actually going to fire, i.e. are separate events generated for subclasses?

    async def set_active(self):
        await CompletableFuture.completed_future(None)

    # Which of these is actually going to fire, i.e. are separate events generated for subclasses?

    async def kill(self):
        self.thread.interrupt()
        return CompletableFuture.completed_future(None)

    # Which of these is actually going to fire, i.e. are separate events generated for subclasses?

    async def interrupt(self):
        self.thread.suspend()
        state_changed(self.thread.status(), JdiReason.Reasons.INTERRUPT)
        return CompletableFuture.completed_future(None)

    # Which of these is actually going to fire, i.e. are separate events generated for subclasses?

    async def pop_frame(self, frame):
        try:
            self.thread.pop_frames(frame)
        except IncompatibleThreadStateException as e:
            print(f"Could not update stack for thread {self}")

        return CompletableFuture.completed_future(None)

    # Which of these is actually going to fire, i.e. are separate events generated for subclasses?

    async def resume(self):
        target_vm.vm.state_changed(TargetExecutionState.RUNNING, JdiReason.Reasons.RESUMED)
        invalidate_and_continue()
        return CompletableFuture.completed_future(None)

    # Which of these is actually going to fire, i.e. are separate events generated for subclasses?

    async def step(self, kind):
        size = StepRequest.STEP_MIN
        depth; match kind:
            case TargetStepKind.INTO: depth = StepRequest.STEP_INTO
            case TargetStepKind.LINE: depth = StepRequest.STEP_LINE
            case TargetStepKind.FINISH | TargetStepKind.ADVANCE: depth = StepRequest.STEP_OUT
            case TargetStepKind.SKIP: depth = StepRequest.STEP_OVER
            default: depth = StepRequest.STEP_MIN

        request = self.event_manager.create_step_request(self.thread, size, depth)
        request.enable()
        invalidate_and_continue()

    def get_stack(self):
        return self.stack

    def get_location(self):
        if not hasattr(self, "location"):
            return None
        return self.location.get_display() if self.location else None

    def set_location(self, location):
        self.location = JdiModelTargetLocation(self, location, False)
        method = location.method()
        impl.register_method(method)

class AsyncFence:
    async def ready(self):
        await CompletableFuture.completed_future(None)

class CompletableFuture:
    @staticmethod
    def completed_future(result=None):
        return result

    @staticmethod
    def then_accept(func):
        return func()

    @staticmethod
    def exceptionally(ex_func):
        return None

    @staticmethod
    def include(future):
        pass

    async def ready(self):
        await CompletableFuture.completed_future(None)

class JdiModelTargetStack:
    # ... implementation ...

class JdiModelTargetRegisterContainer:
    # ... implementation ...
```

Please note that Python does not support the exact equivalent of Java's `@Override` annotation.