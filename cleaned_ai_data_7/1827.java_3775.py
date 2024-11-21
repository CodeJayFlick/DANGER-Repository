class SBStructuredData:
    def __init__(self):
        self._swig_cptr = None
        self._swig_cmemoown = False

    @staticmethod
    def get_cptr(obj):
        if obj is None:
            return 0
        else:
            return obj._swig_cptr

    def delete(self):
        if self._swig_cptr != 0:
            if self._swig_cmemoown:
                self._swig_cmemoown = False
                # Call the equivalent of lldbJNI.delete_ SBStructuredData(self._swig_cptr)
            self._swig_cptr = 0

    def __del__(self):
        self.delete()

    @property
    def is_valid(self):
        return _lldbjni.SBStructuredData_IsValid(self._swig_cptr, self)

    def clear(self):
        _lldbjni.SBStructuredData_Clear(self._swig_cptr, self)

    @property
    def type(self):
        return StructuredDataType(_lldbjni.SBStructuredData_GetType(self._swig_cptr, self))

    @property
    def size(self):
        return _lldbjni.SBStructuredData_GetSize(self._swig_cptr, self)

    def get_keys(self, keys):
        return _lldbjni.SBStructuredData_GetKeys(self._swig_cptr, self, SBStringList.get_cptr(keys), keys)

    def get_value_for_key(self, key):
        return SBStructuredData(_lldbjni.SBStructuredData_GetValueForKey(self._swig_cptr, self, key), True)

    def get_item_at_index(self, idx):
        return SBStructuredData(_lldbjni.SBStructuredData_GetItemAtIndex(self._swig_cptr, self, idx), True)

    def get_integer_value(self, fail_value=None):
        if fail_value is None:
            return _lldbjni.SBStructuredData_GetIntegerValue__SWIG_1(self._swig_cptr, self)
        else:
            return _lldbjni.SBStructuredData_GetIntegerValue__SWIG_0(self._swig_cptr, self, fail_value)

    def get_float_value(self, fail_value=None):
        if fail_value is None:
            return _lldbjni.SBStructuredData_GetFloatValue__SWIG_1(self._swig_cptr, self)
        else:
            return _lldbjni.SBStructuredData_GetFloatValue__SWIG_0(self._swig_cptr, self, fail_value)

    def get_boolean_value(self, fail_value=None):
        if fail_value is None:
            return _lldbjni.SBStructuredData_GetBooleanValue__SWIG_1(self._swig_cptr, self)
        else:
            return _lldbjni.SBStructuredData_GetBooleanValue__SWIG_0(self._swig_cptr, self, fail_value)

    def get_string_value(self):
        dst = bytearray(1024)  # Assuming the maximum size of string
        length = _lldbjni.SBStructuredData_GetStringValue(self._swig_cptr, self, dst, len(dst))
        return str(dst[:length])

    def get_as_json(self, stream):
        error = SBError(_lldbjni.SBStructuredData_GetAsJSON(self._swig_cptr, self, SBStream.get_cptr(stream), stream), True)
        return error

    def get_description(self, stream):
        error = SBError(_lldbjni.SBStructuredData_GetDescription(self._swig_cptr, self, SBStream.get_cptr(stream), stream), True)
        return error

    def set_from_json(self, stream):
        error = SBError(_lldbjni.SBStructuredData_SetFromJSON(self._swig_cptr, self, SBStream.get_cptr(stream), stream), True)
        return error
