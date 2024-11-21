import ctypes

class SBFile:
    def __init__(self):
        self._swig_c_ptr = None
        self._swig_cmemoown = False

    @staticmethod
    def get_cpptr(obj):
        return 0 if obj is None else obj._swig_c_ptr

    def delete(self):
        if self._swig_c_ptr:
            if self._swig_cmemoown:
                ctypes.lldbJNI.delete_SBFile(self._swig_c_ptr)
            self._swig_c_ptr = 0
            self._swig_cmemoown = False

    def __del__(self):
        self.delete()

    @staticmethod
    def make_borrowed(file):
        return SBFile(ctypes.lldbJNI.SBFile_MakeBorrowed(SWIGTYPE_p_std_shared_ptrT_lldb_private_File_t.get_cpptr(file)), True)

    @staticmethod
    def make_forcing_iomethods(force_io_methods):
        return SBFile(ctypes.lldbJNI.SBFile_MakeForcingIOMethods(SWIGTYPE_p_std_shared_ptrT_lldb_private_File_t.get_cpptr(force_io_methods)), True)

    @staticmethod
    def make_borrowed_forcing_iomethods(borrowed_force_io_methods):
        return SBFile(ctypes.lddbJNI.SBFile_MakeBorrowedForcingIOMethods(SWIGTYPE_p_std_shared_ptrT_lldb_private_File_t.get_cpptr(borrowed_force_io_methods)), True)

    def read(self, buf, num_bytes, output):
        return SBError(ctypes.lldbJNI.SBFile_Read(self._swig_c_ptr, self, ctypes.c_char_p(buf), num_bytes, ctypes.c_size_t(output)))

    def write(self, buf, num_bytes, output):
        return SBError(ctypes.lldbJNI.SBFile_Write(self._swig_c_ptr, self, ctypes.c_char_p(buf), num_bytes, ctypes.c_size_t(output)))

    def flush(self):
        ctypes.lldbJNI.SBFile_Flush(self._swig_c_ptr, self)

    def is_valid(self):
        return bool(ctypes.lldbJNI.SBFile_IsValid(self._swig_c_ptr, self))

    def close(self):
        return SBError(ctypes.lldbJNI.SBFile_Close(self._swig_c_ptr, self))

    def get_file(self):
        return SWIGTYPE_p_std_shared_ptrT_lldb_private_File_t(ctypes.lldbJNI.SBFile_GetFile(self._swig_c_ptr, self), True)

class SBError:
    pass

class SWIGTYPE_p_std_shared_ptrT_lldb_private_File_t:
    @staticmethod
    def get_cpptr(file):
        return 0 if file is None else ctypes.c_void_p(1)
