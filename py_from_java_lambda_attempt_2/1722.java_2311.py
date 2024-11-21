Here's your Java code translated into Python:

```Python
class LldbModelTargetRootImpl:
    def __init__(self, impl, schema):
        super().__init__(impl, "Debugger", schema)
        
        self.available = LlldbModelTargetAvailableContainerImpl(self)
        self.connectors = LlldbModelTargetConnectorContainerImpl(self)
        self.sessions = LlldbModelTargetSessionContainerImpl(self)

    def get_focus(self):
        return self.focus

    def set_default_connector(self, default_connector):
        change_attributes([], [], {"parameters": default_connector.get_parameters()}, "Default connector changed")

    def set_focus(self, sel):
        do_fire = not (self.focus == sel)
        
        if do_fire and self.focus:
            focus_path = self.focus.path
            sel_path = sel.path
            
            do_fire = not PathUtils.is_ancestor(sel_path, focus_path)

        if do_fire:
            self.focus = sel
            change_attributes([], [], {"focus": self.focus}, "Focus changed")
        
        return do_fire

    def launch(self, args):
        target_connector = self.connectors.process_launcher
        
        future = model.gate_future(target_connector.launch(args))
        
        return future.exceptionally(lambda exc: DebuggerUserException("Launch failed for " + str(args)))

    def launch(self, args_map):
        target_connector = self.connectors.get_default_connector()
        
        future = model.gate_future(target_connector.launch(args_map))
        
        return future.exceptionally(lambda exc: DebuggerUserException("Launch failed for " + str(args_map)))

    def attach(self, attachable):
        target_connector = self.connectors.process_attacher_by_pid
        
        key = attachable.name
        map = {"pid": key[1:-1]}
        
        future = model.gate_future(target_connector.launch(map))
        
        return future.exceptionally(lambda exc: DebuggerUserException("Launch failed for " + str(key)))

    def attach(self, pid):
        command = LldbAttachCommand(model.get_manager(), str(pid))
        
        future = model.get_manager().execute(command)
        
        return future.then_apply(None)

    def thread_state_changed(self, thread, state, cause, reason):
        target_thread = LlldbModelTargetThread(model.get_model_object(thread))
        
        change_attributes([], [], {"event_object": target_thread}, reason.desc())

    def is_accessible(self):
        return self.accessible
```

Note: This translation assumes that the Java code you provided was part of a larger program, and some parts may not be directly translatable to Python.