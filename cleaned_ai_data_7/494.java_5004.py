class IDebugBreakpoint2:
    IID_IDEBUG_BREAKPOINT2 = "1b278d20-79f2-426e-a3f9-c1ddf375d48e"

    VTIndices2 = {
        'GET_COMMAND_WIDE': 0,
        'SET_COMMAND_WIDE': 1,
        'GET_OFFSET_EXPRESSION_WIDE': 2,
        'SET_OFFSET_EXPRESSION_WIDE': 3
    }

    def get_command_wide(self, buffer: bytes, buffer_size: int):
        pass

    def set_comamnd_wide(self, command: str):
        pass

    def get_offset_expression_wide(self, buffer: bytes, buffer_size: int):
        pass

    def set_offset_expression_wide(self, expression: str):
        pass
