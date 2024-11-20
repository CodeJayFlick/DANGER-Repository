Here is a translation of the Java code into equivalent Python:

```Python
class SBEnvironment:
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
                lldb_jni.delete_SBEnvironment(self.swig_c_ptr)
                self.swig_cmem_own = False
            self.swig_c_ptr = 0

    def __del__(self):
        self.delete()

    @staticmethod
    def new_SBE_0():
        return SBEnvironment(lldb_jni.new_SBEnvironment__SWIG_0(), True)

    @staticmethod
    def new_SBE_1(rhs):
        return SBEnvironment(lldb_jni.new_SBEnvironment__SWIG_1(SBEnvironment.get_c_ptr(rhs), rhs), True)

    @property
    def num_values(self):
        return lldb_jni.SBEnvironment_GetNumValues(self.swig_c_ptr, self)

    def get(self, name):
        return lldb_jni.SBEnvironment_Get(self.swig_c_ptr, self, name)

    def get_name_at_index(self, index):
        return lldb_jni.SBEnvironment_GetNameAtIndex(self.swig_c_ptr, self, index)

    def get_value_at_index(self, index):
        return lldb_jni.SBEnvironment_GetValueAtIndex(self.swig_c_ptr, self, index)

    @property
    def entries(self):
        c_ptr = lldb_jni.SBEnvironment_GetEntries(self.swig_c_ptr, self)
        return SBStringList(c_ptr, True)

    def put_entry(self, name_and_value):
        lldb_jni.SBEnvironment_PutEntry(self.swig_c_ptr, self, name_and_value)

    def set_entries(self, entries, append):
        c_ptr = SBStringList.get_c_ptr(entries)
        lldb_jni.SBEnvironment_SetEntries(self.swig_c_ptr, self, c_ptr, entries, append)

    def set(self, name, value, overwrite):
        return lldb_jni.SBEnvironment_Set(self.swig_c_ptr, self, name, value, overwrite)

    def unset(self, name):
        return lldb_jni.SBEnvironment_Unset(self.swig_c_ptr, self, name)

    def clear(self):
        lldb_jni.SBEnvironment_Clear(self.swig_c_ptr, self)
```

Please note that this is a direct translation of the Java code into Python. The actual functionality and behavior may be different due to differences in languages.