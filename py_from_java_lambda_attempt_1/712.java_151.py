Here is the translation of the Java code into Python:

```Python
class DbgDebugEventCallbacksAdapter:
    def __init__(self, manager):
        self.manager = manager

    def check_interrupt(self, normal):
        if self.manager.get_control().get_interrupt():
            return "BREAK"
        else:
            return normal

    def breakpoint(self, bp):
        print("Breakpoint:", bp.id)
        return self.check_interrupt(self.manager.process_event(DbgBreakpointEvent(bp)))

    def exception(self, exception, first_chance):
        print("Exception:", exception, ", first=", first_chance)
        return self.check_interrupt(self.manager.process_event(DbgExceptionEvent(exception)))

    def create_thread(self, thread_info):
        print("Thread created:", hex(thread_info.handle))
        return self.check_interrupt(self.manager.process_event(DbgThreadCreatedEvent(thread_info)))

    def exit_thread(self, exit_code):
        print("Thread exited:", exit_code)
        return self.check_interrupt(self.manager.process_event(DbgThreadExitedEvent(exit_code)))

    def create_process(self, process_info):
        print("Process created:", hex(process_info.handle))
        print(" Thread created:", hex(process_info.initial_thread_info.handle))
        return self.check_interrupt(self.manager.process_event(DbgProcessCreatedEvent(process_info)))

    def exit_process(self, exit_code):
        print("Process exited:", exit_code)
        print("Thread exited")
        return self.check_interrupt(self.manager.process_event(DbgProcessExitedEvent(exit_code)))

    def load_module(self, module_info):
        print("Module Loaded:", module_info)
        return self.check_interrupt(self.manager.process_event(DbgModuleLoadedEvent(module_info)))

    def unload_module(self, image_base_name, base_offset):
        print("Module Unloaded:", image_base_name, ", " + str(base_offset))
        info = DebugModuleInfo(0L, base_offset, 0, basename(image_base_name), image_base_name, 0, 0)
        return self.check_interrupt(self.manager.process_event(DbgModuleUnloadedEvent(info)))

    def basename(self, path):
        return os.path.basename(path)

    def change_engine_state(self, flags, argument):
        event = DbgStateChangedEvent(flags)
        event.set_argument(argument)
        if flags.contains(ChangeEngineState.EXECUTION_STATUS):
            status = DebugStatus.from_argument(argument)
            print("Execution Status:", status)
            if status == "NO_DEBUGGEE":
                process_count = self.manager.get_process_count()
                event.set_state(process_count > 0 and DbgState.SESSION_EXIT or DbgState.EXIT)
        return self.check_interrupt(self.manager.process_event(event))

    def system_error(self, error, level):
        return self.check_interrupt(self.manager.process_event(DbgSystemErrorEvent(error, level)))

class DebugStatus:
    NO_CHANGE = "NO_CHANGE"
    BREAK = "BREAK"

class ChangeEngineState:
    EXECUTION_STATUS = 1
    BREAKPOINTS = 2
    CURRENT_THREAD = 4
    SYSTEMS = 8

def main():
    manager = None
    adapter = DbgDebugEventCallbacksAdapter(manager)
    # Call the methods of the adapter as needed.

if __name__ == "__main__":
    main()
```

Please note that Python does not have direct equivalent to Java's `package` and `import`, so I did not include them in this translation. Also, some parts of the code are removed because they were commented out or seemed unnecessary for a simple translation from one language to another.