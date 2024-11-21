Here is the translation of the given Java code into equivalent Python:

```Python
class SBTypeSummary:
    def __init__(self):
        self._swig_cptr = None
        self._swig_cmemoown = False

    @staticmethod
    def get_cpptr(obj):
        if obj is None:
            return 0
        else:
            return obj._swig_cptr

    def delete(self):
        if self._swig_cptr != 0:
            if self._swig_cmemoown:
                self._swig_cmemoown = False
                # call the equivalent C++ function here, e.g., lldbJNI.delete_SBTypeSummary()
            self._swig_cptr = 0

    def __del__(self):
        self.delete()

    @staticmethod
    def create_with_summary_string(data, options=0):
        return SBTypeSummary(lldbJNI.SBTypeSummary_CreateWithSummaryString__SWIG_0(data, options), True)

    @staticmethod
    def create_with_function_name(data, options=0):
        return SBTypeSummary(lldbJNI.SBTypeSummary_CreateWithFunctionName__SWIG_0(data, options), True)

    @staticmethod
    def create_with_script_code(data, options=0):
        return SBTypeSummary(lldbJNI.SBTypeSummary_CreateWithScriptCode__SWIG_0(data, options), True)

    def __init__(self, rhs):
        self._swig_cptr = lldbJNI.new_SBTypeSummary__SWIG_1(SBTypeSummary.get_cpptr(rhs), rhs)
        self._swig_cmemoown = True

    def is_valid(self):
        return lldbJNI.SBTypeSummary_IsValid(self._swig_cptr, self)

    def is_equal_to(self, rhs):
        return lldbJNI.SBTypeSummary_IsEqualTo(self._swig_cptr, self, SBTypeSummary.get_cpptr(rhs), rhs)

    def is_function_code(self):
        return lldbJNI.SBTypeSummary_IsFunctionCode(self._swig_cptr, self)

    def is_function_name(self):
        return lldbJNI.SBTypeSummary_IsFunctionName(self._swig_cptr, self)

    def is_summary_string(self):
        return lldbJNI.SBTypeSummary_IsSummaryString(self._swig_cptr, self)

    def get_data(self):
        return lldbJNI.SBTypeSummary_GetData(self._swig_cptr, self)

    def set_summary_string(self, data):
        lldbJNI.SBTypeSummary_SetSummaryString(self._swig_cptr, self, data)

    def set_function_name(self, data):
        lldbJNI.SBTypeSummary_SetFunctionName(self._swig_cptr, self, data)

    def set_function_code(self, data):
        lldbJNI.SBTypeSummary_SetFunctionCode(self._swig_cptr, self, data)

    def get_options(self):
        return lldbJNI.SBTypeSummary_GetOptions(self._swig_cptr, self)

    def set_options(self, arg0):
        lldbJNI.SBTypeSummary_SetOptions(self._swig_cptr, self, arg0)

    def get_description(self, description, description_level):
        return lldbJNI.SBTypeSummary_GetDescription(self._swig_cptr, self, SBStream.get_cpptr(description), description, description_level.swig_value())

    def __str__(self):
        return lldbJNI.SBTypeSummary___str__(self._swig_cptr, self)
```

Please note that you would need to have the equivalent C++ functions (`lldbJNI.*`) implemented in a separate module or library for this Python code to work.