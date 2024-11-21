Here is the equivalent Python code:

```Python
class SBSourceManager:
    def __init__(self):
        pass

    @staticmethod
    def get_c_ptr(obj):
        if obj is None:
            return 0
        else:
            return obj.swig_c_ptr

    def delete(self):
        if self.swig_c_ptr != 0:
            lldb_jni.delete_SBSourceManager(self.swig_c_ptr)
            self.swig_c_ptr = 0

    def __init__(self, rhs):
        this_swig_c_ptr = lldb_jni.new_SBSourceManager(SBSourceManager.get_c_ptr(rhs), rhs)
        this_swig_cmem_own = True
        self.__dict__['swig_c_ptr'] = this_swig_c_ptr
        self.__dict__['swig_cmemoown'] = this_swig_cmemoown

    def display_source_lines_with_line_numbers(self, file, line, context_before, context_after, current_line_cstr, s):
        return lldb_jni.SBSourceManager_DisplaySourceLinesWithLineNumbers(self.swig_c_ptr, self, SBFileSpec.get_c_ptr(file), file, line, context_before, context_after, current_line_cstr, SBStream.get_c_ptr(s), s)

    def display_source_lines_with_line_numbers_and_column(self, file, line, column, context_before, context_after, current_line_cstr, s):
        return lldb_jni.SBSourceManager_DisplaySourceLinesWithLineNumbersAndColumn(self.swig_c_ptr, self, SBFileSpec.get_c_ptr(file), file, line, column, context_before, context_after, current_line_cstr, SBStream.get_c_ptr(s), s)
```

Note: This Python code is not a direct translation of the Java code. It's more like an equivalent implementation in Python. The `@staticmethod` and `__init__` methods are used to mimic the behavior of the original Java code.