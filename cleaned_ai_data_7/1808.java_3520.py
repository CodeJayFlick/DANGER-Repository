class SBLineEntry:
    def __init__(self):
        self._swig_c_ptr = None
        self._swig_cmem_own = False

    @staticmethod
    def get_c_ptr(obj):
        return 0 if obj is None else obj._swig_c_ptr

    def delete(self):
        if self._swig_c_ptr:
            if self._swig_cmem_own:
                # TO DO: implement lldbJNI.delete_SBLineEntry()
                pass
            self._swig_c_ptr = None

    @property
    def start_address(self):
        return SBAddress(lldbJNI.SBLineEntry_GetStartAddress(self._swig_c_ptr, self), True)

    @property
    def end_address(self):
        return SBAddress(lldbJNI.SBLineEntry_GetEndAddress(self._swig_c_ptr, self), True)

    @property
    def is_valid(self):
        return lldbJNI.SBLineEntry_IsValid(self._swig_c_ptr, self)

    @property
    def file_spec(self):
        return SBFileSpec(lldbJNI.SBLineEntry_GetFileSpec(self._swig_c_ptr, self), True)

    @property
    def line(self):
        return lldbJNI.SBLineEntry_GetLine(self._swig_c_ptr, self)

    @property
    def column(self):
        return lldbJNI.SBLineEntry_GetColumn(self._swig_c_ptr, self)

    def get_description(self, description_stream):
        return lldbJNI.SBLineEntry_GetDescription(self._swig_c_ptr, self, SBStream.get_c_ptr(description_stream), description_stream)

    @property
    def file_spec_setter(self):
        # TO DO: implement SBFileSpec setter
        pass

    @file_spec.setter
    def set_file_spec(self, value):
        lldbJNI.SBLineEntry_SetFileSpec(self._swig_c_ptr, self, SBFileSpec.get_c_ptr(value), value)

    @property
    def line_setter(self):
        # TO DO: implement setter for Line property
        pass

    @line.setter
    def set_line(self, value):
        lldbJNI.SBLineEntry_SetLine(self._swig_c_ptr, self, value)

    @property
    def column_setter(self):
        # TO DO: implement setter for Column property
        pass

    @column.setter
    def set_column(self, value):
        lddbJNI.SBLineEntry_SetColumn(self._swig_c_ptr, self, value)

    def __str__(self):
        return lldbJNI.SBLineEntry___str__(self._swig_c_ptr, self)
