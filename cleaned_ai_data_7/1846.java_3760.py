class SBTypeNameSpecifier:
    def __init__(self):
        self._swig_c_ptr = None
        self._swig_cmemoown = False

    @staticmethod
    def get_cpptr(obj):
        if obj is None:
            return 0
        else:
            return obj._swig_c_ptr

    def delete(self):
        if self._swig_c_ptr != 0:
            if self._swig_cmemoown:
                self._swig_cmemoown = False
                # lldbJNI.delete_SBTypeNameSpecifier(self._swig_c_ptr)
            self._swig_c_ptr = 0

    def __del__(self):
        self.delete()

    @staticmethod
    def new_swig_0():
        return SBTypeNameSpecifier()

    @staticmethod
    def new_swig_1(name, is_regex):
        # lldbJNI.new_SBTypeNameSpecifier__SWIG_1(name, is_regex)
        pass

    @staticmethod
    def new_swig_2(name):
        # lldbJNI.new_SBTypeNameSpecifier__SWIG_2(name)
        pass

    @staticmethod
    def new_swig_3(type):
        # lldbJNI.new_SBTypeNameSpecifier__SWIG_3(SBType.get_cpptr(type), type)
        pass

    @staticmethod
    def new_swig_4(rhs):
        # lldbJNI.new_SBTypeNameSpecifier__SWIG_4(SBTypeNameSpecifier.get_cpptr(rhs), rhs)
        pass

    def is_valid(self):
        return True  # Replace with actual implementation from lldbJNI.SBTypeNameSpecifier_IsValid()

    def is_equal_to(self, rhs):
        return self.is_valid() and SBTypeNameSpecifier.new_swig_1("name", False) == rhs
        # Replace with actual implementation from lldbJNI.SBTypeNameSpecifier_IsEqualTo

    def get_name(self):
        return "Name"  # Replace with actual implementation from lldbJNI.SBTypeNameSpecifier_GetName()

    def get_type(self):
        return SBType()  # Replace with actual implementation from lldbJNI.SBTypeNameSpecifier_GetType()
        pass

    def is_regex(self):
        return True  # Replace with actual implementation from lldbJNI.SBTypeNameSpecifier_IsRegex()

    def get_description(self, description, level):
        return self.is_valid() and SBStream().write(description)
        # Replace with actual implementation from lldbJNI.SBTypeNameSpecifier_GetDescription

    def __str__(self):
        return "SBTypeNameSpecifier"  # Replace with actual implementation from lldbJNI.SBTypeNameSpecifier___str__()
