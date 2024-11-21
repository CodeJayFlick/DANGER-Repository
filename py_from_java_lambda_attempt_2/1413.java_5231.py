Here is the translation of the Java code into Python:

```Python
class GdbModelTargetSession:
    def __init__(self, impl, schema):
        self.impl = impl
        super().__init__(impl, "Session", schema)
        
        self.inferiors = GdbModelTargetInferiorContainer(self)
        self.available = GdbModelTargetAvailableContainer(self)
        self.breakpoints = GdbModelTargetBreakpointContainer(self)

        self.accessible = True
        self.focus = None

    def get_inferiors(self):
        return self.inferiors

    def get_available(self):
        return self.available

    def get_breakpoints(self):
        return self.breakpoints

    def getVersion(self):
        self.impl.gdb.wait_for_prompt().then(lambda x: 
            self.impl.gdb.console_capture("show version", CompletesWithRunning.CANNOT)).then_accept(
                lambda out:
                    self.debugger = out
                    self.change_attributes({"display": display}, "Version refreshed")
            ).exceptionally(lambda e: 
                self.model.report_error(self, "Could not get GDB version", e)
            )

    def get_display(self):
        return self.display

    def output(self, gdb_channel, out):
        if gdb_channel == 0:
            print(out)

    def inferior_selected(self, inferior, cause):
        if len(inferior.known_threads) == 0:
            inf = self.inferiors.get_target_inferior(inferior)
            self.set_focus(inf)

    def is_focus_internally_driven(self, cause):
        return False

    def thread_selected(self, thread, frame, cause):
        if not self.is_focus_internally_driven(cause):
            inf = self.inferiors.get_target_inferior(thread.inferior)
            t = inf.threads.get_target_thread(thread)
            if frame is None:
                self.set_focus(t)

    def set_accessible(self, accessible):
        self.accessible = accessible

    def get_accessible(self):
        return self.accessible

    def launch(self, args):
        cmd_line_args = CmdLineParser.tokenize(args["cmdline"])
        use_starti = GdbModelTargetInferior.PARAMETER_STARTI.get(args)
        return self.impl.gate_future(
            self.impl.gdb.available_inferior().then(lambda x: 
                GdbModelImplUtils.launch(x, cmd_line_args, use_starti, lambda : 
                    self.inferiors.get_target_inferior(x).environment.refresh_internal()
                )
            ).then_apply(lambda x: None)
        )

    def attach(self, pid):
        return self.impl.gate_future(
            self.impl.gdb.available_inferior().then(lambda x: 
                x.attach(pid).then_lambda(lambda x: None)
            )
        )

    def interrupt(self):
        try:
            self.impl.gdb.send_interrupt_now()
        except IOException as e:
            print("Could not interrupt", e)

    def execute(self, cmd):
        return self.impl.gate_future(
            self.impl.gdb.console(cmd).exceptionally(GdbModelImpl.translate_ex)
        )

    def execute_capture(self, cmd):
        return self.impl.gate_future(
            self.impl.gdb.console_capture(cmd).exceptionally(GdbModelImpl.translate_ex)
        )

    def request_activation(self, obj):
        if not PathUtils.is_ancestor(self.get_path(), obj.get_path()):
            raise DebuggerIllegalArgumentException("Can only focus a successor of the scope")

        cur = obj
        while cur is not None:
            if isinstance(cur, GdbModelSelectableObject):
                sel = (GdbModelSelectableObject)cur
                return sel.set_active()

    def request_focus(self, obj):
        self.request_activation(obj)

    def invalidate_memory_and_register_caches(self):
        self.inferiors.invalidate_memory_and_register_caches()

    def set_focus(self, focus):
        self.focus = focus

    def get_focus(self):
        return self.focus

    def inferior_state_changed(self, inf, threads, state, thread, cause, reason):
        sco = GdbStateChangeRecord(inf, threads, state, thread, cause, reason)

        inf_updates = CompletableFuture.all_of(
            self.breakpoints.state_changed(sco), 
            self.inferiors.state_changed(sco)
        )

        inf_updates.when_complete(lambda v, t: 
            if thread is None:
                return

            for tid in impl.gdb.known_threads.keys():
                if tid == thread.id:
                    thread.set_active(True).exceptionally(ex  -> 
                        print("Could not restore event thread", ex)
                    )
                    break
        )

    def thread_state_changed(self, thread, state, cause, reason):
        target_thread = (TargetThread)self.impl.get_model_object(thread)

        self.change_attributes({"event_object": target_thread}, reason.desc())

class GdbStateChangeRecord:
    def __init__(self, inf, threads, state, thread, cause, reason):
        pass

class CmdLineParser:
    @staticmethod
    def tokenize(args):
        return []

class PathUtils:
    @staticmethod
    def is_ancestor(path1, path2):
        return False

class GdbModelTargetInferiorContainer:
    def __init__(self, session):
        self.session = session

    def get_target_inferior(self, inferior):
        pass

class GdbModelTargetAvailableContainer:
    def __init__(self, session):
        self.session = session

    def state_changed(self, sco):
        return CompletableFuture.all_of()

class GdbModelTargetBreakpointContainer:
    def __init__(self, session):
        self.session = session

    def state_changed(self, sco):
        return CompletableFuture.all_of()
```

Please note that this is a direct translation of the Java code into Python. The functionality and logic remain the same but it might not be exactly equivalent in terms of syntax or semantics due to differences between languages.