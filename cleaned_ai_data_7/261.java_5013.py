class DefaultModuleRecorder:
    def __init__(self, recorder):
        self.recorder = recorder
        self.trace = recorder.get_trace()
        self.module_manager = trace.get_module_manager()

    def do_record_process_module(self, snap, module):
        path = module.get_joined_path(".")
        if not self.recorder.memory_mapper:
            print(f"Got module before memory mapper: {path}")
            return None

        exists = self.module_manager.get_loaded_module_by_path(snap, path)
        if exists:
            return exists

        try:
            target_range = module.get_range()
            if target_range is None:
                print(f"Range not found for {module}")
                return None
            trace_range = self.recorder.memory_mapper.target_to_trace(target_range)
            return self.module_manager.add_loaded_module(path, module.get_name(), trace_range, snap)
        except DuplicateNameException as e:
            # This resolves the race condition, since DB access is synchronized
            return self.module_manager.get_loaded_module_by_path(snap, path)

    def offer_process_module(self, module):
        snap = self.recorder.snap
        path = module.get_joined_path(".")
        self.recorder.par_tx.execute(f"Module {path} loaded", lambda: self.do_record_process_module(snap, module), path)

    def do_record_process_module_section(self, snap, section):
        path = section.get_joined_path(".")
        if not self.recorder.memory_mapper:
            print(f"Got module section before memory mapper: {path}")
            return None
        trace_module = self.do_record_process_module(snap, section.module)
        if trace_module is None:
            return None  # Failure should already be logged

        try:
            target_range = section.get_range()
            trace_range = self.recorder.memory_mapper.target_to_trace(target_range)
            return trace_module.add_section(path, section.index, trace_range)
        except DuplicateNameException as e:
            print(f"{path} already recorded")
            return self.module_manager.get_loaded_section_by_path(snap, path)

    def offer_process_module_section(self, section):
        snap = self.recorder.snap
        path = section.get_joined_path(".")
        self.recorder.par_tx.execute(f"Section {path} added", lambda: self.do_record_process_module_section(snap, section), section.module.get_joined_path("."))

    def do_remove_process_module(self, snap, module):
        path = module.get_joined_path(".")
        trace_module = self.module_manager.get_loaded_module_by_path(snap, path)
        if not trace_module:
            print(f"unloaded {path} is not in the trace")
            return
        try:
            if trace_module.loaded_snap == snap:
                print("Observed module unload in the same snap as its load")
                #recorder.create_snapshot("WARN: Module removed", event_thread, tid)
            else:
                trace_module.set_unloaded_snap(snap)
        except DuplicateNameException as e:
            print(f"Could not record process module removed: {e}")

    def remove_process_module(self, module):
        snap = self.recorder.snap
        path = module.get_joined_path(".")
        self.recorder.par_tx.execute(f"Module {path} unloaded", lambda: self.do_remove_process_module(snap, module), path)

    def get_trace_module(self, module):
        path = module.get_joined_path(".")
        return self.module_manager.get_loaded_module_by_path(self.recorder.snap, path)

    def get_trace_section(self, section):
        path = section.get_joined_path(".")
        return self.module_manager.get_loaded_section_by_path(self.recorder.snap, path)
