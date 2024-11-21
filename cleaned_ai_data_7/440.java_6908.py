import ctypes
from enum import Enum

class BreakFlags(Enum):
    pass  # Define your own break flags here

class Machine:
    @staticmethod
    def get_by_number(number: int) -> 'Machine':
        return None  # Implement this method to map numbers to machines

class WrapIDebugClient:
    def __init__(self, client_ptr: ctypes.POINTER):
        self.client_ptr = client_ptr

    def QueryInterface(self):
        pass  # Implement the query interface here

    def Release(self):
        pass  # Implement the release function here


class DebugBreakpointImpl1:
    def __init__(self, jna_breakpoint: 'IDebugBreakpoint'):
        self.cleanable = None
        self.jna_breakpoint = jna_breakpoint

    def set_control(self, control: 'DebugControlInternal'):
        self.control = control

    def remove(self):
        if hasattr(self, 'control') and self.control is not None:
            self.control.remove_breakpoint(self.jna_breakpoint)
        self.jna_breakpoint = None

    def get_id(self) -> int:
        pul_id = ctypes.c_ulong(0)
        result = self.jna_breakpoint.get_id(pul_id)
        return pul_id.value

    def get_type(self) -> 'BreakFullType':
        break_type_ptr = ctypes.POINTER(ctypes.c_ulong)(None)
        proc_type_ptr = ctypes.POINTER(ctypes.c_ulong)(None)
        result = self.jna_breakpoint.get_type(break_type_ptr, proc_type_ptr)

        if result == 0:
            return BreakFullType(BreakType.values()[break_type_ptr.contents.value], Machine.get_by_number(proc_type_ptr.contents.value))
        else:
            raise Exception("Failed to get breakpoint type")

    def get_adder(self) -> 'DebugClient':
        client_ptr = ctypes.POINTER(ctypes.c_void_p)(None)
        result = self.jna_breakpoint.get_adder(client_ptr)

        if result == 0:
            return WrapIDebugClient(client_ptr.contents)
        else:
            raise Exception("Failed to get adder")

    def get_flags(self) -> 'BitmaskSet[BreakFlags]':
        flags_ptr = ctypes.POINTER(ctypes.c_ulonglong)(None)
        result = self.jna_breakpoint.get_flags(flags_ptr)

        if result == 0:
            return BitmaskSet(BreakFlags, flags_ptr.contents.value)
        else:
            raise Exception("Failed to get breakpoint flags")

    def add_flags(self, *flags: 'BreakFlags'):
        ul_flags = ctypes.c_ulonglong(0)
        for flag in flags:
            ul_flags |= flag.value
        result = self.jna_breakpoint.add_flags(ul_flags)

        if result == 0:
            return
        else:
            raise Exception("Failed to add breakpoint flags")

    def remove_flags(self, *flags: 'BreakFlags'):
        ul_flags = ctypes.c_ulonglong(0)
        for flag in flags:
            ul_flags |= flag.value
        result = self.jna_breakpoint.remove_flags(ul_flags)

        if result == 0:
            return
        else:
            raise Exception("Failed to remove breakpoint flags")

    def set_flags(self, *flags: 'BreakFlags'):
        ul_flags = ctypes.c_ulonglong(0)
        for flag in flags:
            ul_flags |= flag.value
        result = self.jna_breakpoint.set_flags(ul_flags)

        if result == 0:
            return
        else:
            raise Exception("Failed to set breakpoint flags")

    def get_offset(self) -> int | None:
        pull_offset_ptr = ctypes.POINTER(ctypes.c_ulonglong)(None)
        result = self.jna_breakpoint.get_offset(pull_offset_ptr)

        if result == 0x80004005:  # E_NOINTERFACE
            return None

        if result != 0:
            raise Exception("Failed to get breakpoint offset")

        return pull_offset_ptr.contents.value

    def set_offset(self, offset: int):
        ull_offset = ctypes.c_ulonglong(offset)
        result = self.jna_breakpoint.set_offset(ull_offset)

        if result != 0:
            raise Exception("Failed to set breakpoint offset")

    def get_offset_expression(self) -> str | None:
        pul_expression_size_ptr = ctypes.POINTER(ctypes.c_ulong)(None)
        buffer = bytearray()
        result = self.jna_breakpoint.get_offset_expression(None, 0, pul_expression_size_ptr)

        if result == 0x80004005:  # E_NOINTERFACE
            return None

        if result != 0:
            raise Exception("Failed to get breakpoint offset expression")

        buffer.extend((pul_expression_size_ptr.contents.value - len(buffer)) * b'\0')
        self.jna_breakpoint.get_offset_expression(buffer, pul_expression_size_ptr.contents.value, None)
        return str(buffer)

    def set_offset_expression(self, expression: str):
        result = self.jna_breakpoint.set_offset_expression(expression.encode())

        if result != 0:
            raise Exception("Failed to set breakpoint offset expression")

    def get_data_parameters(self) -> 'BreakDataParameters':
        pul_size_ptr = ctypes.POINTER(ctypes.c_ulong)(None)
        pul_access_type_ptr = ctypes.POINTER(ctypes.c_ulonglong)(None)
        result = self.jna_breakpoint.get_data_parameters(pul_size_ptr, pul_access_type_ptr)

        if result == 0:
            return BreakDataParameters(pul_size_ptr.contents.value, BitmaskSet(BreakAccess, pul_access_type_ptr.contents.value))
        else:
            raise Exception("Failed to get breakpoint data parameters")

    def set_data_parameters(self, params: 'BreakDataParameters'):
        self.set_data_parameters(params.size, params.access)

    def set_data_parameters(self, size: int, access: BitmaskSet['BreakAccess']):
        ul_size = ctypes.c_ulong(size)
        ul_access_type = ctypes.c_ulonglong(access.get_bitmask())
        result = self.jna_breakpoint.set_data_parameters(ul_size, ul_access_type)

        if result != 0:
            raise Exception("Failed to set breakpoint data parameters")
