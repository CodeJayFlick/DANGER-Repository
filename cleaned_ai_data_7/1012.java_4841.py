class DataModelScriptDebugImpl:
    def __init__(self, jna_data):
        self.cleanable = DbgModel.release_when_phantom(self, jna_data)
        self.jna_data = jna_data

    def get_pointer(self):
        return self.jna_data.get_pointer()

# The following methods are not implemented in this interface
def query_virtual(offset):
    raise NotImplementedError("Not implemented in this interface")

def read_virtual_uncached(offset, into, len):
    if len > into.remaining():
        raise BufferOverflowError()
    ull_offset = ULONGLONG(int(offset))
    ul_len = ULONG(len)
    pul_bytes_read = ULONGByReference()
    COMUtils.check_rc(self.jna_data.read_virtual(ull_offset, into, ul_len, pul_bytes_read))
    read = int(pul_bytes_read.value)
    into.position(read + into.position())
    return read

def write_virtual_uncached(offset, from, len):
    if len > from.remaining():
        raise BufferOverflowError()
    ull_offset = ULONGLONG(int(offset))
    ul_len = ULONG(len)
    pul_bytes_written = ULONGByReference()
    COMUtils.check_rc(self.jna_data.write_virtual(ull_offset, from, ul_len, pul_bytes_written))
    written = int(pul_bytes_written.value)
    from.position(written + from.position())
    return written

class ULONGLONG:
    def __init__(self, value):
        self.value = value

class ULONGByReference:
    pass

class COMUtils:
    @staticmethod
    def check_rc(rc):
        if rc != 0:
            raise Exception("COM error")
