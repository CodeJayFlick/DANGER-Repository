class NoisyDebugEventCallbacksAdapter:
    def __init__(self, default_status):
        self.default_status = default_status

    def create_process(self, debug_process_info):
        print(f"createProcess: {debug_process_info}")
        return self.default_status

    def create_thread(self, debug_thread_info):
        print(f"createThread: {debug_thread_info}")
        return self.default_status

    def exit_process(self, exit_code):
        print(f"exitProcess: {hex(exit_code)}")
        return self.default_status

    def breakpoint(self, bp):
        print(f"breakpoint: {bp}")
        return self.default_status

    def change_debuggee_state(self, flags, argument):
        print(f"changeDebuggeeState: {flags}, {hex(argument)}")
        return self.default_status

    def change_engine_state(self, flags, argument):
        if flags.contains(ChangeEngineState.EXECUTION_STATUS):
            status = DebugStatus.values()[(argument & 0x0_ffff_ffffL)]
            print(f"changeEngineState: {flags}, {hex(argument)} ({status})")
        else:
            print(f"changeEngineState: {flags}, {hex(argument)}")
        return self.default_status

    def change_symbol_state(self, flags, argument):
        print(f"changeSymbolState: {flags}, {hex(argument)}")
        return self.default_status

    def exception(self, exception, first_chance):
        print(f"exception: {exception}, {first_chance}")
        return self.default_status

    def exit_thread(self, exit_code):
        print(f"exitThread: {hex(exit_code)}")
        return self.default_status

    def load_module(self, debug_module_info):
        print(f"loadModule: {debug_module_info}")
        return self.default_status

    def session_status(self, status):
        print(f"sessionStatus: {status}")
        return self.default_status

    def system_error(self, error, level):
        print(f"systemError: {error}, {level}")
        return self.default_status

    def unload_module(self, image_base_name, base_offset):
        print(f"unloadModule: {image_base_name}, {base_offset}")
        return self.default_status
