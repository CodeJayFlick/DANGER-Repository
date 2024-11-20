class SBLanguageRuntime:
    def __init__(self):
        self.swigCPtr = None
        self.swigCMemOwn = False

    @staticmethod
    def get_cptr(obj):
        if obj is None:
            return 0
        else:
            return obj.swigCPtr

    def delete(self):
        if self.swigCPtr != 0:
            if self.swigCMemOwn:
                # This line will be replaced with actual implementation in Python wrapper.
                pass
            self.swigCPtr = 0

    @staticmethod
    def get_language_type_from_string(string):
        return lldbJNI.SBLanguageRuntime_GetLanguageTypeFromString(string)

    @staticmethod
    def get_name_for_language_type(language):
        return lldbJNI.SBLanguageRuntime_GetNameForLanguageType(language)
