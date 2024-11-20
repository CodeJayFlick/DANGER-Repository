import jna.platform.win32 as win32
from dbgeng import DEBUG_VALUE, IDebugRegisters2
from com.sun.jna.platform.win32 import COMUtils

class DebugRegistersImpl2:
    def __init__(self, jna_registers):
        super().__init__(jna_registers)
        self.jna_registers = jna_registers

    def doGetValues(self, source: int, ul_count: int, pul_indices: list[int], p_values: list[DEBUG_VALUE]):
        ul_source = win32.ULONG(source)
        COMUtils.check_rc(
            self.jna_registers.GetValues2(ul_source, ul_count, pul_indices, 0, p_values))

    def doSetValues(self, source: int, ul_count: int, pul_indices: list[int], p_values: list[DEBUG_VALUE]):
        ul_source = win32.ULONG(source)
        COMUtils.check_rc(
            self.jna_registers.SetValues2(ul_source, ul_count, pul_indices, 0, p_values))
