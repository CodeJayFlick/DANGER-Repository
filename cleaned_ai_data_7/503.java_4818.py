class IDebugClient5:
    IID_IDEBUG_CLIENT5 = "e3acb9d7-7ec2-4f0c-a0da-e81e0cbbe628"

    class VTIndices5(enum):
        ATTACH_KERNEL_WIDE = 1
        GET_KERNEL_CONNECTION_OPTIONS_WIDE = 2
        SET_KERNEL_CONNECTION_OPTIONS_WIDE = 3
        START_PROCESS_SERVER_WIDE = 4
        CONNECT_PROCESS_SERVER_WIDE = 5
        START_SERVER_WIDE = 6
        OUTPUT_SERVERS_WIDE = 7
        GET_OUTPUT_CALLBACKS_WIDE = 8
        SET_OUTPUT_CALLBACKS_WIDE = 9
        GET_OUTPUT_LINE_PREFIX_WIDE = 10
        SET_OUTPUT_LINE_PREFIX_WIDE = 11
        GET_IDENTITY_WIDE = 12
        OUTPUT_IDENTITY_WIDE = 13
        GET_EVENT_CALLBACKS_WIDE = 14
        SET_EVENT_CALLBACKS_WIDE = 15
        CREATE_PROCESS2 = 16
        CREATE_PROCESS2_WIDE = 17
        CREATE_PROCESS_AND_ATTACH2 = 18
        CREATE_PROCESS_AND_ATTACH2_WIDE = 19
        PUSH_OUTPUT_LINE_PREFIX = 20
        PUSH_OUTPUT_LINE_PREFIX_WIDE = 21
        POP_OUTPUT_LINE_PREFIX = 22
        GET_NUMBER_INPUT_CALLBACKS = 23
        GET_NUMBER_OUTPUT_CALLBACKS = 24
        GET_NUMBER_EVENT_CALLBACKS = 25
        GET_QUIT_LOCK_STRING = 26
        SET_QUIT_LOCK_STRING = 27
        GET_QUIT_LOCK_STRING_WIDE = 28
        SET_QUIT_LOCK_STRING_WIDE = 29

    start = VTIndices4.follow(VTIndices5)

    def get_index(self):
        return self.ordinal() + IDebugClient5.start


class HRESULT:
    pass


def attach_kernel_wide(flags, connect_options):
    # implement this method in Python
    pass


def get_kernel_connection_options_wide(buffer, buffer_size, options_size):
    # implement this method in Python
    pass


# and so on for all the methods...
