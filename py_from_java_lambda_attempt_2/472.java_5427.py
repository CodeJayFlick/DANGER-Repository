Here is the translation of the given Java code into Python:

```Python
import comtypes
from ghidra_comm.util import BitmaskSet

class DebugRegistersImpl1:
    def __init__(self, jna_registers):
        self.cleanable = None  # OpaqueCleanable not available in Python
        self.jna_registers = jna_registers

    @property
    def number_registers(self):
        pul_number = comtypes.ULONGLONG()
        result = self.jna_registers.GetNumberRegisters(pul_number)
        return int(pul_number.value)

    def get_description(self, register_index):
        ul_reg_idx = comtypes.ULONG(register_index)
        pul_name_size = comtypes.ULONGByReference()
        desc = self.jna_registers.GetDescription(ul_reg_idx, None, 0, pul_name_size, None)
        name = bytearray(pul_name_size.value)
        result_desc = self.jna_registers.GetDescription(ul_reg_idx, name, pul_name_size.value, None, desc)

        return DebugRegisterDescription(
            str(name.decode('utf-8')),
            register_index,
            DebugValueType(result_desc.Type),
            BitmaskSet(DebugRegisterFlags, result_desc.Flags),
            int(result_desc.SubregMaster),
            int(result_desc.SubregLength),
            long(result_desc.SubregMask),
            int(result_desc.SubregShift)
        )

    def get_index_by_name(self, name):
        pul_index = comtypes.ULONGByReference()
        hr = self.jna_registers.GetIndexByName(name, pul_index)

        if hr == COMUtilsExtra.E_NOINTERFACE:
            return -1

        result = int(pul_index.value)
        return result

    def get_value(self, index):
        ul_index = comtypes.ULONG(index)
        dv_val = self.jna_registers.GetValue(ul_index)
        return DebugValue.from_debug_value(dv_val)

    @staticmethod
    def do_get_values(source, ul_count, pul_indices, p_values):
        if source != DebugRegisterSource.DEBUG_REGSRC_DEBUGGEE:
            raise ValueError("This interface only permits DEBUG_REGSRC_DEBUGGEE")

        result = self.jna_registers.GetValues(ul_count, pul_indices, 0, p_values)
        return result

    def get_values(self, source, indices):
        if not indices:
            return {}

        li = list(indices)
        ul_count = comtypes.ULONG(len(li))
        pul_indices = [comtypes.ULONG(i) for i in li]
        p_values = [DebugValue.from_debug_value(Debug_VALUE())] * len(li)

        self.do_get_values(source, ul_count, pul_indices, p_values)

        result = {i: DebugValue.from_debug_value(pv) for i, pv in zip(li, p_values)}
        return result

    def set_value(self, index, value):
        ul_index = comtypes.ULONG(index)
        dv_val = DEBUG_VALUE().from_debug_value(value)
        self.jna_registers.SetValue(ul_index, dv_val)

    @staticmethod
    def do_set_values(source, ul_count, pul_indices, p_values):
        if source != DebugRegisterSource.DEBUG_REGSRC_DEBUGGEE:
            raise ValueError("This interface only permits DEBUG_REGSRC_DEBUGGEE")

        result = self.jna_registers.SetValues(ul_count, pul_indices, 0, p_values)
        return result

    def set_values(self, source, values):
        if not values:
            return

        li = list(values.keys())
        ul_count = comtypes.ULONG(len(li))
        pul_indices = [comtypes.ULONG(i) for i in li]
        p_values = [DebugValue.from_debug_value(Debug_VALUE())] * len(li)

        for i, (k, v) in enumerate(zip(li, values.values())):
            pul_indices[i].value = k
            DEBUG_VALUE().from_debug_value(p_values[i]).value = v

        self.do_set_values(source, ul_count, pul_indices, p_values)
```

Please note that the Python code above is a direct translation of the given Java code. It might not be optimal or idiomatic for Python programming and may require adjustments to work correctly in your specific use case.

Also, this code uses `comtypes` library which provides a way to access COM components from Python.