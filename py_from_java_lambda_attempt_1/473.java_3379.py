Here is the translation of the Java code to Python:
```python
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
```
Note that I've used the `jna` library to interact with the Windows API, and imported the necessary classes from the `dbgeng` module. The rest of the code is a straightforward translation of the Java methods to Python.

Also, please note that this code assumes you have the `jna` library installed and configured correctly in your Python environment. If not, you can install it using pip: `pip install jna`.