class SBBlock:
    def __init__(self):
        self._swig_cptr = 0
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
                lldbJNI.delete_SBBlock(self._swig_cptr)
            self._swig_cptr = 0

    @property
    def is_inlined(self):
        return lldbJNI.SBBlock_IsInlined(self._swig_cptr, self)

    @property
    def is_valid(self):
        return lldbJNI.SBBlock_IsValid(self._swig_cptr, self)

    def get_inlined_name(self):
        return lldbJNI.SBBlock_GetInlinedName(self._swig_cptr, self)

    def get_inlined_call_site_file(self):
        return SBFileSpec(lldbJNI.SBBlock_GetInlinedCallSiteFile(self._swig_cptr, self), True)

    def get_inlined_call_site_line(self):
        return lldbJNI.SBBlock_GetInlinedCallSiteLine(self._swig_cptr, self)

    def get_inlined_call_site_column(self):
        return lldbJNI.SBBlock_GetInlinedCallSiteColumn(self._swig_cptr, self)

    @property
    def parent(self):
        return SBBlock(lldbJNI.SBBlock_GetParent(self._swig_cptr, self), True)

    @property
    def containing_inlined_block(self):
        return SBBlock(lldbJNI.SBBlock_GetContainingInlinedBlock(self._swig_cptr, self), True)

    @property
    def sibling(self):
        return SBBlock(lldbJNI.SBBlock_GetSibling(self._swig_cptr, self), True)

    @property
    def first_child(self):
        return SBBlock(lldbJNI.SBBlock_GetFirstChild(self._swig_cptr, self), True)

    def get_num_ranges(self):
        return lldbJNI.SBBlock_GetNumRanges(self._swig_cptr, self)

    def get_range_start_address(self, idx):
        return SBAddress(lldbJNI.SBBlock_GetRangeStartAddress(self._swig_cptr, self, idx), True)

    def get_range_end_address(self, idx):
        return SBAddress(lldbJNI.SBBlock_GetRangeEndAddress(self._swig_cptr, self, idx), True)

    def get_range_index_for_block_address(self, block_addr):
        return lldbJNI.SBBlock_GetRangeIndexForBlockAddress(self._swig_cptr, self, SBAddress.get_c_ptr(block_addr), block_addr)

    def get_description(self, description):
        return lldbJNI.SBBlock_GetDescription(self._swig_cptr, self, SBStream.get_c_ptr(description), description)

    def get_variables(self, frame, arguments, locals, statics, use_dynamic):
        if not hasattr(self, '_variables'):
            self._variables = SBValueList(lldbJNI.SBBlock_GetVariables__SWIG_0(self._swig_cptr, self, SBFrame.get_c_ptr(frame), frame, arguments, locals, statics, use_dynamic.swig_value()), True)
        return self._variables

    def __str__(self):
        return lldbJNI.SBBlock___str__(self._swig_cptr, self)

class SBFileSpec:
    pass
