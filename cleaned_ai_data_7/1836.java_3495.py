import llvmlite.binding as lldbJNI
from enum import Enum

class TraceType(Enum):
    pass  # Define your trace types here


class SBTraceOptions:
    def __init__(self, c_ptr=None, own=False):
        self._swig_cptr = c_ptr
        self._swig_own = own

    @staticmethod
    def get_c_ptr(obj):
        return obj._swig_cptr if obj else 0

    def delete(self):
        if self._swig_cptr:
            if self._swig_own:
                lldbJNI.delete_SBTraceOptions(self._swig_cptr)
                self._swig_own = False
            self._swig_cptr = 0

    @property
    def type(self):
        return TraceType(llbJNi.SBTraceOptions_get_type(self._swig_cptr))

    @type.setter
    def type(self, value):
        lldbJNI.SBTraceOptions_set_type(self._swig_cptr, self, value.value)

    @property
    def trace_buffer_size(self):
        return llbJNi.SBTraceOptions_get_trace_buffer_size(self._swig_cptr)

    @trace_buffer_size.setter
    def trace_buffer_size(self, size):
        lldbJNI.SBTraceOptions_set_trace_buffer_size(self._swig_cptr, self, size)

    @property
    def meta_data_buffer_size(self):
        return llbJNi.SBTraceOptions_get_meta_data_buffer_size(self._swig_cptr)

    @meta_data_buffer_size.setter
    def meta_data_buffer_size(self, size):
        lldbJNI.SBTraceOptions_set_meta_data_buffer_size(self._swig_cptr, self, size)

    @property
    def thread_id(self):
        return llbJNi.SBTraceOptions_get_thread_id(self._swig_cptr)

    @thread_id.setter
    def thread_id(self, value):
        lldbJNI.SBTraceOptions_set_thread_id(self._swig_cptr, self, value)

    def is_valid(self):
        return llbJNi.SBTraceOptions_is_valid(self._swig_cptr)
