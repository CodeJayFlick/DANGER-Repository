import ctypes

class IDebugEventCallbacksWide:
    IID_IDEBUG_EVENT_CALLBACKS_WIDE = "0690e046-9c23-45ac-a04f-987ac29ad0d3"

    def __init__(self):
        pass

    def get_interest_mask(self) -> int:
        # To be implemented
        return 0

    def breakpoint(self, bp: 'WrapIDebugBreakpoint') -> int:
        # To be implemented
        return 0

    def exception(self, exception: 'EXCEPTION_RECORD64', first_chance: bool) -> int:
        # To be implemented
        return 0

    def create_thread(self, handle: int, data_offset: int, start_offset: int) -> int:
        # To be implemented
        return 0

    def exit_thread(self, exit_code: int) -> int:
        # To be implemented
        return 0

    def create_process(self, image_file_handle: int, handle: int, base_offset: int,
                       module_size: int, module_name: str, image_name: str, check_sum: int,
                       time_date_stamp: int, initial_thread_handle: int, thread_data_offset: int,
                       start_offset: int) -> int:
        # To be implemented
        return 0

    def exit_process(self, exit_code: int) -> int:
        # To be implemented
        return 0

    def load_module(self, image_file_handle: int, base_offset: int, module_size: int,
                    module_name: str, image_name: str, check_sum: int, time_date_stamp: int) -> int:
        # To be implemented
        return 0

    def unload_module(self, image_base_name: str, base_offset: int) -> int:
        # To be implemented
        return 0

    def system_error(self, error: int, level: int) -> int:
        # To be implemented
        return 0

    def session_status(self, status: int) -> int:
        # To be implemented
        return 0

    def change_debuggee_state(self, flags: int, argument: int) -> int:
        # To be implemented
        return 0

    def change_engine_state(self, flags: int, argument: int) -> int:
        # To be implemented
        return 0

    def change_symbol_state(self, flags: int, argument: int) -> int:
        # To be implemented
        return 0
