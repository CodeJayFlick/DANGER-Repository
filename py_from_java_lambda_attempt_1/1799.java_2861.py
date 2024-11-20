Here is a translation of the Java code into equivalent Python:

```Python
class SBFileSpec:
    def __init__(self):
        self._swig_cptr = None
        self._swig_cmemoown = False

    @staticmethod
    def get_c_ptr(obj):
        if obj is None:
            return 0
        else:
            return obj._swig_cptr

    def delete(self):
        if self._swig_cptr != 0:
            if self._swig_cmemoown:
                self._swig_cmemoown = False
                # Call the equivalent of lldbJNI.delete_SBFileSpec()
            self._swig_cptr = 0

    @property
    def swig_cptr(self):
        return self._swig_cptr

    @swig_cptr.setter
    def swig_cptr(self, value):
        if self._swig_cmemoown:
            # Call the equivalent of lldbJNI.delete_SBFileSpec()
        self._swig_cptr = value

    @property
    def swig_cmemoown(self):
        return self._swig_cmemoown

    @swig_cmemoown.setter
    def swig_cmemoown(self, value):
        if self._swig_cmemoown:
            # Call the equivalent of lldbJNI.delete_SBFileSpec()
        self._swig_cmemoown = value

    def __init__(self, c_ptr=True, cmemoown=False):
        self.swig_cptr = c_ptr
        self.swig_cmemoown = cmemoown

    @property
    def is_valid(self):
        return lldbJNI.SBFileSpec_IsValid(self._swig_cptr)

    @property
    def exists(self):
        return lldbJNI.SBFileSpec_Exists(self._swig_cptr)

    def resolve_executable_location(self):
        return lldbJNI.SBFileSpec_ResolveExecutableLocation(self._swig_cptr)

    @property
    def filename(self):
        return lldbJNI.SBFileSpec_GetFilename(self._swig_cptr)

    @filename.setter
    def filename(self, value):
        lldbJNI.SBFileSpec_SetFilename(self._swig_cptr, value)

    @property
    def directory(self):
        return lldbJNI.SBFileSpec_GetDirectory(self._swig_cptr)

    @directory.setter
    def directory(self, value):
        lldbJNI.SBFileSpec_SetDirectory(self._swig_cptr, value)

    def get_path(self, dst_ path, dst_len):
        return lldbJNI.SBFileSpec_GetPath(self._swig_cptr, dst_path, dst_len)

    @staticmethod
    def resolve_path(src_path, dst_path, dst_len):
        return lldbJNI.SBFileSpec_ResolvePath(src_path, dst_path, dst_len)

    def get_description(self, description):
        return lldbJNI.SBFileSpec_GetDescription(self._swig_cptr, description)

    def append_component_part(self, file_or_directory):
        lldbJNI.SBFileSpec_AppendPathComponent(self._swig_cptr, file_or_directory)

    def __str__(self):
        return lldbJNI.SBFileSpec___str__(self._swig_cptr)
```

Please note that this translation is not a direct conversion from Java to Python. It's more of an equivalent implementation in Python based on the provided code.