Here is the translation of the given Java code into equivalent Python:

```Python
import llvmlite as lldb
from enum import Enum

class DescriptionLevel(Enum):
    Any = 0
    Enabled = 1
    Disabled = 2


class SBBreakpointLocation:
    def __init__(self, c_ptr=None, own=False):
        self._swig_cptr = c_ptr
        self._own = own

    @staticmethod
    def get_c_ptr(obj):
        return obj._swig_cptr if obj else None

    def delete(self):
        if self._swig_cptr:
            lldb.delete_SBBreakpointLocation(self._swig_cptr)
            self._swig_cptr = 0
            self._own = False

    @property
    def id(self):
        return lldb.SBBreakpointLocation_GetID(self._swig_cptr)

    @property
    def is_valid(self):
        return lldb.SBBreakpointLocation_IsValid(self._swig_cptr) != 0

    @property
    def address(self):
        addr = lldb.SBBreakpointLocation_GetAddress(self._swig_cptr)
        if not isinstance(addr, SBAddress):
            raise ValueError("Invalid Address")
        return addr

    @property
    def load_address(self):
        return lldb.SBBreakpointLocation_GetLoadAddress(self._swig_cptr)

    def set_enabled(self, enabled):
        lldb.SBBreakpointLocation_SetEnabled(self._swig_cptr, enabled)

    @property
    def is_enabled(self):
        return lldb.SBBreakpointLocation_IsEnabled(self._swig_cptr) != 0

    @property
    def hit_count(self):
        return lldb.SBBreakpointLocation_GetHitCount(self._swig_cptr)

    @property
    def ignore_count(self):
        return lldb.SBBreakpointLocation_GetIgnoreCount(self._swig_cptr)

    def set_ignore_count(self, n):
        lldb.SBBreakpointLocation_SetIgnoreCount(self._swig_cptr, n)

    def set_condition(self, condition):
        lldb.SBBreakpointLocation_SetCondition(self._swig_cptr, condition)

    @property
    def condition(self):
        return lldb.SBBreakpointLocation_GetCondition(self._swig_cptr)

    @property
    def auto_continue(self):
        return lldb.SBBreakpointLocation_GetAutoContinue(self._swig_cptr) != 0

    def set_auto_continue(self, enabled):
        lldb.SBBreakpointLocation_SetAutoContinue(self._swig_cptr, enabled)

    def set_script_callback_function(self, callback_func_name):
        lldb.SBBreakpointLocation_SetScriptCallbackFunction__SWIG_0(self._swig_cptr, callback_func_name)

    @property
    def script_callback_body(self):
        return lldb.SBBreakpointLocation_GetScriptCallbackBody(self._swig_cptr)

    def set_command_line_commands(self, commands):
        lldb.SBBreakpointLocation_SetCommandLineCommands(self._swig_cptr, SBStringList.get_c_ptr(commands), commands)

    @property
    def command_line_commands(self):
        return lldb.SBBreakpointLocation_GetCommandLineCommands(self._swig_cptr, SBStringList.get_c_ptr())

    def set_thread_id(self, thread_id):
        lldb.SBBreakpointLocation_SetThreadID(self._swig_cptr, thread_id)

    @property
    def thread_id(self):
        return lldb.SBBreakpointLocation_GetThreadID(self._swig_cptr)

    def set_thread_index(self, index):
        lldb.SBBreakpointLocation_SetThreadIndex(self._swig_cptr, index)

    @property
    def thread_index(self):
        return lldb.SBBreakpointLocation_GetThreadIndex(self._swig_cptr)

    def set_thread_name(self, name):
        lldb.SBBreakpointLocation_SetThreadName(self._swig_cptr, name)

    @property
    def thread_name(self):
        return lldb.SBBreakpointLocation_GetThreadName(self._swig_cptr)

    def set_queue_name(self, queue_name):
        lldb.SBBreakpointLocation_SetQueueName(self._swig_cptr, queue_name)

    @property
    def queue_name(self):
        return lldb.SBBreakpointLocation_GetQueueName(self._swig_cptr)

    @property
    def is_resolved(self):
        return lldb.SBBreakpointLocation_IsResolved(self._swig_cptr) != 0

    def get_description(self, description, level):
        return lldb.SBBreakpointLocation_GetDescription(self._swig_cptr, self, SBStream.get_c_ptr(description), description, level.value)

    @property
    def breakpoint(self):
        bp = lldb.SBBreakpointLocation_GetBreakpoint(self._swig_cptr)
        if not isinstance(bp, SBBreakpoint):
            raise ValueError("Invalid Breakpoint")
        return bp

    def __str__(self):
        return lldb.SBBreakpointLocation___str__(self._swig_cptr)

class SBAddress:
    pass  # This class is missing in the given Java code.

class SBError:
    pass  # This class is missing in the given Java code.

class SBStringList:
    @staticmethod
    def get_c_ptr(obj):
        return obj if isinstance(obj, SBStringList) else None

class SBStream:
    @staticmethod
    def get_c_ptr(obj):
        return obj if isinstance(obj, SBStream) else None