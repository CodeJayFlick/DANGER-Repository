class IDebugControl4:
    IID_IDEBUG_CONTROL4 = "94e60ce9-9b41-4b19-9fc0-6d9eb35272b3"

    class VTIndices4(enum.IntEnum):
        GET_LOG_FILE_WIDE = 1
        OPEN_LOG_FILE_WIDE = 2
        INPUT_WIDE = 3
        RETURN_INPUT_WIDE = 4
        OUTPUT_WIDE = 5
        OUTPUT_VA_LIST_WIDE = 6
        CONTROLLED_OUTPUT_WIDE = 7
        CONTROLLED_OUTPUT_VA_LIST_WIDE = 8
        OUTPUT_PROMPT_WIDE = 9
        OUTPUT_PROMPT_VA_LIST_WIDE = 10
        GET_PROMPT_TEXT_WIDE = 11
        ASSEMBLE_WIDE = 12
        DISASSEMBLE_WIDE = 13
        GET_PROCESSOR_TYPE_NAMES_WIDE = 14
        GET_TEXT_MACRO_WIDE = 15
        SET_TEXT_MACRO_WIDE = 16
        EVALUATE_WIDE = 17
        EXECUTE_WIDE = 18
        EXECUTE_COMMAND_FILE_WIDE = 19
        GET_BREAKPOINT_BY_INDEX2 = 20
        GET_BREAKPOINT_BY_ID2 = 21
        ADD_BREAKPOINT2 = 22
        REMOVE_BREAKPOINT2 = 23
        ADD_EXTENSION_WIDE = 24
        GET_EXTENSION_BY_PATH_WIDE = 25
        CALL_EXTENSION_WIDE = 26
        GET_EXTENSION_FUNCTION_WIDE = 27
        GET_EVENT_FILTER_TEXT_WIDE = 28
        GET_EVENT_FILTER_COMMAND_WIDE = 29
        SET_EVENT_FILTER_COMMAND_WIDE = 30
        GET_SPECIFIC_FILTER_ARGUMENT_WIDE = 31
        SET_SPECIFIC_FILTER_ARGUMENT_WIDE = 32
        GET_EXCEPTION_FILTER_SECOND_COMMAND_WIDE = 33
        SET_EXCEPTION_FILTER_SECOND_COMMAND_WIDE = 34
        GET_LAST_EVENT_INFORMATION_WIDE = 35
        GET_TEXT_REPLACEMENT_WIDE = 36
        SET_TEXT_REPLACEMENT_WIDE = 37
        SET_EXPRESSION_SYNTAX_BY_NAME_WIDE = 38
        GET_EXPRESSION_SYNTAX_NAMES_WIDE = 39
        GET_EVENT_INDEX_DESCRIPTION_WIDE = 40
        GET_LOG_FILE2 = 41
        OPEN_LOG_FILE2 = 42
        GET_LOG_FILE2_WIDE = 43
        OPEN_LOG_FILE2_WIDE = 44
        GET_SYSTEM_VERSION_VALUES = 45
        GET_SYSTEM_VERSION_STRING = 46
        GET_SYSTEM_VERSION_STRING_WIDE = 47
        GET_CONTEXT_STACK_TRACE = 48
        OUTPUT_CONTEXT_STACK_TRACE = 49
        GET_STORED_EVENT_INFORMATION = 50
        GET_MANAGED_STATUS = 51
        GET_MANAGED_STATUS_WIDE = 52
        RESET_MANAGED_STATUS = 53

    @classmethod
    def start(cls):
        return VTIndices4.follow(VTIndices3)

    def get_index(self) -> int:
        return self.ordinal() + IDebugControl4.VTIndices4.start


class DEBUG_VALUE:
    pass


def add_breakpoint2(type: int, desired_id: int, bp: POINTER) -> HRESULT:
    # implement the method
    pass


def return_input_wide(buffer: WSTRING) -> HRESULT:
    # implement the method
    pass


def output_wide(mask: int, format: WSTRING, *objects) -> HRESULT:
    # implement the method
    pass


def output_prompt_wide(output_control: int, format: WSTRING, *objects) -> HRESULT:
    # implement the method
    pass


def get_prompt_text_wide(buffer: bytearray, buffer_size: int, text_size: POINTERBYREFERENCE) -> HRESULT:
    # implement the method
    pass


def evaluate_wide(expression: WSTRING, desired_type: int, value: DEBUG_VALUE, remainder_index: POINTERBYREFERENCE) -> HRESULT:
    # implement the method
    pass


def execute_wide(output_control: int, command: WSTRING, flags: int) -> HRESULT:
    # implement the method
    pass

