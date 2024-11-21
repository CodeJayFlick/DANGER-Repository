Here is the translation of the given Java code into equivalent Python:

```Python
import unittest
from ghidra.dbg.target import *
from ghidra.dbg.test.abstract_debugger_model_scenario_registers_test import AbstractDebuggerModelScenarioRegistersTest

class AbstractModelForLldbScenarioX64RegistersTest(AbstractDebuggerModelScenarioRegistersTest):
    def get_specimen(self):
        return "MacOSSpecimen.REGISTERS"

    def get_breakpoint_expression(self):
        return "break_here"

    def get_register_writes(self):
        register_writes = {"rcx": bytes.fromhex("00410000")}
        return register_writes

    def verify_expected_effect(self, process):
        status = process.get_typed_attribute_now_by_name(LldbModelTargetProcessImpl.EXIT_CODE_ATTRIBUTE_NAME, 0)
        self.assertTrue(status == 0x41 or status == 0)

    def perform_register_writes(self, target, to_write):
        c = m.find_with_index("0", target.path).get()
        banks = [bank for bank in m.findall(TargetRegisterBank) if bank.get_path() == c.get_path()]
        for name, value in to_write.items():
            for bank in banks:
                regs = [reg for reg in m.findall(TargetRegister) 
                        if reg.get_path() == bank.get_path() and reg.name == name]
                for reg in regs:
                    bank.write_register(reg, value)
```

Please note that this Python code is not a direct translation of the given Java code. It's an equivalent implementation using Python syntax and semantics.