from enum import Enum

class ExecutionState(Enum):
    RUNNING = 0
    STOPPED = 1

class DebugStatus(Enum):
    NO_CHANGE = (False, None, 13)
    GO = (True, ExecutionState.RUNNING, 10)
    GO_HANDLED = (True, ExecutionState.RUNNING, 9)
    GO_NOT_HANDLED = (True, ExecutionState.RUNNING, 8)
    STEP_OVER = (True, ExecutionState.RUNNING, 7)
    STEP_INTO = (True, ExecutionState.RUNNING, 5)
    BREAK = (False, ExecutionState.STOPPED, 0)
    NO_DEBUGGEE = (True, None, 1)
    STEP_BRANCH = (True, ExecutionState.RUNNING, 6)
    IGNORE_EVENT = (False, None, 11)
    RESTART_REQUESTED = (True, None, 12)
    REVERSE_GO = (True, None, 0xff)
    REVERSE_STEP_BRANCH = (True, None, 0xff)
    REVERSE_STEP_OVER = (True, None, 0xff)
    REVERSE_STEP_INTO = (True, None, 0xff)
    OUT_OF_SYNC = (False, None, 2)
    WAIT_INPUT = (False, None, 3)
    TIMEOUT = (False, None, 4)

class SessionStatus(Enum):
    ACTIVE = 0
    END_SESSION_ACTIVE_TERMINATE = 1
    END_SESSION_ACTIVE_DETACH = 2
    END_SESSION_PASSIVE = 3
    END = 4
    REBOOT = 5
    HIBERNATE = 6
    FAILURE = 7

class BitmaskUniverse(Enum):
    pass

class DebugAttachFlags(BitmaskUniverse):
    DEFAULT = 0
    NONINVASIVE = 1 << 0
    EXISTING = 1 << 1
    NONINVASIVE_NO_SUSPEND = 1 << 2
    INVASIVE_NO_INITIAL_BREAK = 1 << 3
    INVASIVE_RESUME_PROCESS = 1 << 4
    NONINVASIVE_ALLOW_PARTIAL = 1 << 5

class DebugCreateFlags(BitmaskUniverse):
    DEBUG_PROCESS = WinBase.DEBUG_PROCESS
    DEBUG_ONLY_THIS_PROCESS = WinBase.DEBUG_ONLY_THIS_PROCESS
    CREATE_SUSPENDED = WinBase.CREATE_SUSPENDED
    DETACHED_PROCESS = WinBase.DETACHED_PROCESS
    CREATE_NEW_CONSOLE = WinBase.CREATE_NEW_CONSOLE
    # NORMAL_PRIORITY_CLASS = WinBase.NORMAL_PRIORITY_CLASS,
    # IDLE_PRIORITY_CLASS = WinBase.IDLE_PRIORITY_CLASS,
    # HIGH_PRIORITY_CLASS = WinBase.HIGH_PRIORITY_CLASS,
    # REALTIME_PRIORITY_CLASS = WinBase.REALTIME_PRIORITY_CLASS,
    CREATE_NEW_PROCESS_GROUP = WinBase.CREATE_NEW_PROCESS_GROUP
    CREATE_UNICODE_ENVIRONMENT = WinBase.CREATE_UNICODE_ENVIRONMENT
    CREATE_SEPARATE_WOW_VDM = WinBase.CREATE_SEPARATE_WOW_VDM
    CREATE_SHARED_WOW_VDM = WinBase.CREATE_SHARED_WOW_VDM
    CREATE_FORCEDOS = WinBase.CREATE_FORCEDOS

class DebugEndSessionFlags(Enum):
    DEBUG_END_PASSIVE = 0x00000000
    DEBUG_END_ACTIVE_TERMINATE = 0x00000001
    DEBUG_END_ACTIVE_DETACH = 0x00000002
    DEBUG_END_REENTRANT = 0x00000003
    DEBUG_END_DISCONNECT = 0x00000004

class DebugOutputFlags(Enum):
    DEBUG_OUTPUT_NORMAL = 0x1
    DEBUG_OUTPUT_ERROR = 0x2
    DEBUG_OUTPUT_WARNING = 0x4
    DEBUG_OUTPUT_VERBOSE = 0x8
    DEBUG_OUTPUT_PROMPT = 0x10
    DEBUG_OUTPUT_PROMPT_REGISTERS = 0x20
    DEBUG_OUTPUT_EXTENSION_WARNING = 0x40
    DEBUG_OUTPUT_DEBUGGEE = 0x80
    DEBUG_OUTPUT_DEBUGGEE_PROMPT = 0x100
    DEBUG_OUTPUT_SYMBOLS = 0x200

class DebugServerId:
    pass

def get_advanced(self):
    # implement this method in your class
    pass

def get_control(self):
    # implement this method in your class
    pass

def get_data_spaces(self):
    # implement this method in your class
    pass

def get_registers(self):
    # implement this method in your class
    pass

def get_symbols(self):
    # implement this method in your class
    pass

def get_system_objects(self):
    # implement this method in your class
    pass

def attach_kernel(self, flags, options):
    # implement this method in your class
    pass

def start_process_server(self, options):
    # implement this method in your class
    pass

def connect_process_server(self, options):
    # implement this method in your class
    pass

def dispatch_callbacks(self, timeout):
    # implement this method in your class
    pass

def flush_callbacks(self):
    # implement this method in your class
    pass

class DebugClient:
    def __init__(self):
        self.advanced = None
        self.control = None
        self.data_spaces = None
        self.registers = None
        self.symbols = None
        self.system_objects = None

    def attach_kernel(self, flags, options):
        pass

    # ... and so on for all the other methods.
