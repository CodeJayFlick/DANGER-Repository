class SBTypeFormat:
    def __init__(self):
        self._swig_cptr = None
        self._swig_cmemoown = False

    @staticmethod
    def get_cpptr(obj):
        return 0 if obj is None else obj._swig_cptr

    def delete(self):
        if self._swig_cptr != 0:
            if self._swig_cmemoown:
                self._swig_cmemoown = False
                #lldbJNI.delete_SBTypeFormat(self._swig_cptr)
            self._swig_cptr = 0

    def __del__(self):
        self.delete()

    @staticmethod
    def new_swig_0():
        return SBTypeFormat()

    @staticmethod
    def new_swig_1(format, options):
        #lldbJNI.new_SBTypeFormat__SWIG_1(format.swigValue(), options)
        pass

    @staticmethod
    def new_swig_2(format):
        #lldbJNI.new_SBTypeFormat__SWIG_2(format.swigValue())
        pass

    @staticmethod
    def new_swig_3(type, options):
        #lldbJNI.new_SBTypeFormat__SWIG_3(type, options)
        pass

    @staticmethod
    def new_swig_4(type):
        #lldbJNI.new_SBTypeFormat__SWIG_4(type)
        pass

    @staticmethod
    def new_swig_5(rhs):
        #lldbJNI.new_SBTypeFormat__SWIG_5(SBTypeFormat.get_cpptr(rhs), rhs)
        pass

    def is_valid(self):
        return False  # lldbJNI.SBTypeFormat_IsValid(self._swig_cptr, self)

    def is_equal_to(self, rhs):
        return False  # lldbJNI.SBTypeFormat_IsEqualTo(self._swig_cptr, self, SBTypeFormat.get_cpptr(rhs), rhs)

    @property
    def format(self):
        pass

    @format.setter
    def set_format(self, arg0):
        pass

    @property
    def type_name(self):
        return None  # lldbJNI.SBTypeFormat_GetTypeName(self._swig_cptr, self)

    @type_name.setter
    def set_type_name(self, arg0):
        pass

    @property
    def options(self):
        return 0  # lldbJNI.SBTypeFormat_GetOptions(self._swig_cptr, self)

    @options.setter
    def set_options(self, arg0):
        pass

    def get_description(self, description, level):
        return False  # lldbJNI.SBTypeFormat_GetDescription(self._swig_cptr, self, SBStream.get_cpptr(description), description, level.swigValue())

    def __str__(self):
        return None  # lldbJNI.SBTypeFormat___str__(self._swig_cptr, self)
