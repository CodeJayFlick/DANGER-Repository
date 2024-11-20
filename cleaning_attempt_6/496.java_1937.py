class WrapIDebugBreakpoint:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        self.pv_instance = pv_instance

    def get_id(self) -> int:
        # implement _invokeHR and VTIndices.GET_ID here
        return 0

    def get_type(self) -> tuple[int, int]:
        # implement _invokeHR and VTIndices.GET_TYPE here
        return (0, 0)

    def get_adder(self):
        # implement _invokeHR and VTIndices.GET_ADDER here
        pass

    def get_flags(self) -> int:
        # implement _invokeHR and VTIndices.GET_FLAGS here
        return 0

    def add_flags(self, flags: int) -> int:
        # implement _invokeHR and VTIndices.ADD_FLAGS here
        return 0

    def remove_flags(self, flags: int) -> int:
        # implement _invokeHR and VTIndices.REMOVE_FLAGS here
        return 0

    def set_flags(self, flags: int) -> int:
        # implement _invokeHR and VTIndices.SET_FLAGS here
        return 0

    def get_offset(self) -> int:
        # implement _invokeHR and VTIndices.GET_OFFSET here
        return 0

    def set_offset(self, offset: int) -> int:
        # implement _invokeHR and VTIndices.SET_OFFSET here
        return 0

    def get_data_parameters(self) -> tuple[int, int]:
        # implement _invokeHR and VTIndices.GET_DATA_PARAMETERS here
        return (0, 0)

    def set_data_parameters(self, size: int, access_type: int) -> int:
        # implement _invokeHR and VTIndices.SET_DATA_PARAMETERS here
        return 0

    def get_pass_count(self) -> int:
        # implement _invokeHR and VTIndices.GET_PASS_COUNT here
        return 0

    def set_pass_count(self, count: int) -> int:
        # implement _invokeHR and VTIndices.SET_PASS_COUNT here
        return 0

    def get_current_pass_count(self) -> int:
        # implement _invokeHR and VTIndices.GET_CURRENT_PASS_COUNT here
        return 0

    def get_match_thread_id(self) -> int:
        # implement _invokeHR and VTIndices.GET_MATCH_THREAD_ID here
        return 0

    def set_match_thread_id(self, thread: int) -> int:
        # implement _invokeHR and VTIndices.SET_MATCH_THREAD_ID here
        return 0

    def get_command(self, buffer: bytes, buffer_size: int, command_size: int):
        # implement _invokeHR and VTIndices.GET_COMMAND here
        pass

    def set_command(self, command: str) -> int:
        # implement _invokeHR and VTIndices.SET_COMMAND here
        return 0

    def get_offset_expression(self, buffer: bytes, buffer_size: int, expression_size: int):
        # implement _invokeHR and VTIndices.GET_OFFSET_EXPRESSION here
        pass

    def set_offset_expression(self, expression: str) -> int:
        # implement _invokeHR and VTIndices.SET_OFFSET_EXPRESSION here
        return 0

    def get_parameters(self) -> tuple[int]:
        # implement _invokeHR and VTIndices.GET_PARAMETERS here
        return (0,)
