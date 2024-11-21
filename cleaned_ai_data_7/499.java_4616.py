from enum import Enum
import struct

class VTIndices(Enum):
    ATTACH_KERNEL = 1
    GET_KERNEL_CONNECTION_OPTIONS = 2
    SET_KERNEL_CONNECTION_OPTIONS = 3
    START_PROCESS_SERVER = 4
    CONNECT_PROCESS_SERVER = 5
    DISCONNECT_PROCESS_SERVER = 6
    GET_RUNNING_PROCESS_SYSTEM_IDS = 7
    GET RUNNING PROCESS SYSTEM ID BY EXECUTABLE NAME = 8
    GET_RUNNING_PROCESS_DESCRIPTION = 9
    ATTACH_PROCESS = 10
    CREATE_PROCESS = 11
    CREATE_PROCESS_AND_ATTACH = 12
    GET_PROCESS_OPTIONS = 13
    ADD_PROCESS_OPTIONS = 14
    REMOVE_PROCESS_OPTIONS = 15
    SET_PROCESS_OPTIONS = 16
    OPEN_DUMP_FILE = 17
    WRITE_DUMP_FILE = 18
    CONNECTION_SESSION = 19
    START_SERVER = 20
    OUTPUT_SERVERS = 21
    TERMINATE_PROCESSES = 22
    DETACH_PROCESSES = 23
    END_SESSION = 24
    GET_EXIT_CODE = 25
    DISPATCH_CALLBACKS = 26
    EXIT_DISPATCH = 27
    CREATE_CLIENT = 28
    GET_INPUT_CALLBACKS = 29
    SET_INPUT_CALLBACKS = 30
    GET_OUTPUT_CALLBACKS = 31
    SET_OUTPUT_CALLBACKS = 32
    GET_OUTPUT_MASK = 33
    SET_OUTPUT_MASK = 34
    GET_OTHER_OUTPUT_MASK = 35
    SET_OTHER_OUTPUT_MASK = 36
    GET_OUTPUT_WIDTH = 37
    SET_OUTPUT_WIDTH = 38
    GET_OUTPUT_LINE_PREFIX = 39
    SET_OUTPUT_LINE_PREFIX = 40
    GET_IDENTITY = 41
    OUTPUT_IDENTITY = 42
    GET_EVENT_CALLBACKS = 43
    SET_EVENT_CALLBACKS = 44
    FLUSH_CALLBACKS = 45

class IDebugClient:
    def __init__(self):
        self.IID_IDEBUG_CLIENT = "27fe5639-8407-4f47-8364-ee118fb08ac8"

    def AttachKernel(self, Flags: int, ConnectOptions: str) -> int:
        pass

    def GetKernelConnectionOptions(self, Buffer: bytes, BufferSize: int, OptionsSize: int) -> int:
        pass

    def SetKernelConnectionOptions(self, Options: str) -> int:
        pass

    def StartProcessServer(self, Flags: int, Options: str, Reserved: object) -> int:
        pass

    def ConnectProcessServer(self, RemoteOptions: str, Server: int) -> int:
        pass

    def DisconnectProcessServer(self, Server: int) -> int:
        pass

    def GetRunningProcessSystemIds(self, Server: int, Ids: list[int], Count: int, ActualCount: int) -> int:
        pass

    def GetRunningProcessSystemIdByExecutableName(self, Server: int, ExeName: str, Flags: int, Id: int) -> int:
        pass

    def GetRunningProcessDescription(self, Server: int, SystemId: int, Flags: int, ExeName: bytes, ExeNameSize: int, ActualExeNameSize: int, Description: bytes, DescriptionSize: int, ActualDescriptionSize: int) -> int:
        pass

    def AttachProcess(self, Server: int, ProcessId: int, AttachFlags: int) -> int:
        pass

    def CreateProcess(self, Server: int, CommandLine: str, CreateFlags: int) -> int:
        pass

    def CreateProcessAndAttach(self, Server: int, CommandLine: str, CreateFlags: int, pid: int, AttachFlags: int) -> int:
        pass

    def GetProcessOptions(self) -> int:
        pass

    def AddProcessOptions(self, Options: int) -> int:
        pass

    def RemoveProcessOptions(self, Options: int) -> int:
        pass

    def SetProcessOptions(self, Options: int) -> int:
        pass

    def OpenDumpFile(self, DumpFile: str) -> int:
        pass

    def WriteDumpFile(self, DumpFile: str, Qualifier: int) -> int:
        pass

    def ConnectSession(self, Flags: int, HistoryLimit: int) -> int:
        pass

    def StartServer(self, Options: str) -> int:
        pass

    def OutputServers(self, OutputControl: int, Machine: str, Flags: int) -> int:
        pass

    def TerminateProcesses(self) -> int:
        pass

    def DetachProcesses(self) -> int:
        pass

    def EndSession(self, Flags: int) -> int:
        pass

    def GetExitCode(self) -> int:
        pass

    def DispatchCallbacks(self, Timeout: int) -> int:
        pass

    def ExitDispatch(self, Client: IDebugClient) -> int:
        pass

    def CreateClient(self, Client: object) -> int:
        pass

    def GetInputCallbacks(self) -> object:
        pass

    def SetInputCallbacks(self, Callbacks: object) -> int:
        pass

    def GetOutputCallbacks(self) -> object:
        pass

    def SetOutputCallbacks(self, Callbacks: object) -> int:
        pass

    def GetOutputMask(self) -> int:
        pass

    def SetOutputMask(self, Mask: int) -> int:
        pass

    def GetOtherOutputMask(self, Client: IDebugClient, Mask: int) -> int:
        pass

    def SetOtherOutputMask(self, Client: IDebugClient, Mask: int) -> int:
        pass

    def GetOutputWidth(self) -> int:
        pass

    def SetOutputWidth(self, Columns: int) -> int:
        pass

    def GetOutputLinePrefix(self, Buffer: bytes, BufferSize: int, PrefixSize: int) -> int:
        pass

    def SetOutputLinePrefix(self, Prefix: str) -> int:
        pass

    def GetIdentity(self, Buffer: bytes, BufferSize: int, IdentitySize: int) -> int:
        pass

    def OutputIdentity(self, OutputControl: int, Flags: int, Format: str) -> int:
        pass

    def GetEventCallbacks(self) -> object:
        pass

    def SetEventCallbacks(self, Callbacks: object) -> int:
        pass

    def FlushCallbacks(self) -> int:
        pass
