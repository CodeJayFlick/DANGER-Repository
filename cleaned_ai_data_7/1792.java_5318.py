class SBDeclaration:
    def __init__(self):
        self.swig_c_ptr = None
        self.swig_cmem_own = False

    @staticmethod
    def get_c_ptr(obj):
        if obj is None:
            return 0
        else:
            return obj.swig_c_ptr

    def delete(self):
        if self.swig_c_ptr != 0:
            if self.swig_cmem_own:
                lldb_jni.delete_SBDeclaration(self.swig_c_ptr)
                self.swig_cmem_own = False
            self.swig_c_ptr = 0

    def __del__(self):
        self.delete()

    @property
    def is_valid(self):
        return lldb_jni.SBDeclaration_IsValid(self.swig_c_ptr)

    @property
    def file_spec(self):
        if not hasattr(self, '_file_spec'):
            self._file_spec = SBFileSpec(lldb_jni.SBDeclaration_GetFileSpec(self.swig_c_ptr), True)
        return self._file_spec

    @property
    def line(self):
        return lldb_jni.SBDeclaration_GetLine(self.swig_c_ptr)

    @line.setter
    def line(self, value):
        lldb_jni.SBDeclaration_SetLine(self.swig_c_ptr, value)

    @property
    def column(self):
        return lldb_jni.SBDeclaration_GetColumn(self.swig_c_ptr)

    @column.setter
    def column(self, value):
        lldb_jni.SBDeclaration_SetColumn(self.swig_c_ptr, value)

    def get_description(self, description_stream):
        return lldb_jni.SBDeclaration_GetDescription(self.swig_c_ptr, self, SBStream.get_c_ptr(description_stream), description_stream)

    @property
    def description(self):
        if not hasattr(self, '_description'):
            self._description = SBStream(lldb_jni.SBDeclaration_GetDescription(self.swig_c_ptr, self))
        return self._description

    def set_file_spec(self, file_spec):
        lldb_jni.SBDeclaration_SetFileSpec(self.swig_c_ptr, self, SBFileSpec.get_c_ptr(file_spec), file_spec)

    def __str__(self):
        return lldb_jni.SBDeclaration___str__(self.swig_c_ptr)
