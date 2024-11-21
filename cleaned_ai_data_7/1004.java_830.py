import ctypes
from comtypes import BSTR, POINTER


class DataModelScriptTemplateImpl:
    def __init__(self, jna_data):
        self.cleanable = None  # Not sure what this should be in Python
        self.jna_data = jna_data

    def get_pointer(self):
        return self.jna_data.get_pointer()

    def get_name(self):
        bref = BSTR()
        result = ctypes.windll.oleaut32.SysAllocStringW(b'')
        try:
            rc = self.jna_data.GetName(result)
            template_name = result.value.decode('utf-16le').strip('\0')
        finally:
            ctypes.windll.oleaut32.SysFreeString(result)

        return template_name

    def get_description(self):
        bref = BSTR()
        result = ctypes.windll.oleaut32.SysAllocStringW(b'')
        try:
            rc = self.jna_data.GetDescription(result)
            template_description = result.value.decode('utf-16le').strip('\0')
        finally:
            ctypes.windll.oleaut32.SysFreeString(result)

        return template_description

    def get_content(self):
        pp_content_stream = POINTER()
        try:
            rc = self.jna_data.GetContent(pp_content_stream)
            wrap = WrapIUnknownEx(pp_content_stream.value)
            return UnknownExInternal.tryPreferredInterfaces(wrap.QueryInterface())
        finally:
            wrap.Release()


class WrapIUnknownEx:
    def __init__(self, ptr):
        self.ptr = ptr

    def QueryInterface(self):
        # Not sure what this should be in Python
        pass


class UnknownExInternal:
    @staticmethod
    def tryPreferredInterfaces(query_interface):
        # Not sure what this should be in Python
        pass


# Note: You may need to install the comtypes library if you haven't already.
