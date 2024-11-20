class SBSymbol:
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
                #lldbJNI.delete_SBSymbol(self._swig_cptr)
            self._swig_cptr = 0

    def __del__(self):
        self.delete()

    def is_valid(self):
        return lldbJNI.SBSymbol_IsValid(self._swig_cptr, self)

    def get_name(self):
        return lldbJNI.SBSymbol_GetName(self._swig_cptr, self)

    def get_display_name(self):
        return lldbJNI.SBSymbol_GetDisplayName(self._swig_cptr, self)

    def get_mangled_name(self):
        return lddbJNI.SBSymbol_GetMangledName(self._swig_cptr, self)

    def get_instructions(self, target):
        if isinstance(target, SBTarget):
            return SBInstructionList(lldbJNI.SBSymbol_GetInstructions_0(self._swig_cptr, self, SBTarget.get_c_ptr(target), target))
        else:
            raise TypeError("target must be an instance of SBTarget")

    def get_instructions(self, target, flavor_string):
        if isinstance(target, SBTarget):
            return SBInstructionList(lldbJNI.SBSymbol_GetInstructions_1(self._swig_cptr, self, SBTarget.get_c_ptr(target), target, flavor_string))
        else:
            raise TypeError("target must be an instance of SBTarget")

    def get_start_address(self):
        return SBAddress(lldbJNI.SBSymbol_GetStartAddress(self._swig_cptr, self))

    def get_end_address(self):
        return SBAddress(lldbJNI.SBSymbol_GetEndAddress(self._swig_cptr, self))

    def get_prologue_byte_size(self):
        return lldbJNI.SBSymbol_GetPrologueByteSize(self._swig_cptr, self)

    def get_type(self):
        return SymbolType.swig_to_enum(lldbJNI.SBSymbol_GetType(self._swig_cptr, self))

    def get_description(self, description_stream):
        if isinstance(description_stream, SBStream):
            return lldbJNI.SBSymbol_GetDescription(self._swig_cptr, self, SBStream.get_c_ptr(description_stream), description_stream)
        else:
            raise TypeError("description_stream must be an instance of SBStream")

    def is_external(self):
        return lldbJNI.SBSymbol_IsExternal(self._swig_cptr, self)

    def is_synthetic(self):
        return lddbJNI.SBSymbol_IsSynthetic(self._swig_cptr, self)

    def __str__(self):
        return lldbJNI.SBSymbol___str__(self._swig_cptr, self)
