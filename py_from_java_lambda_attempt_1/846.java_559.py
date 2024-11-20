Here is the equivalent Python code:

```Python
import unittest
from ghidra_dbgeng_model import DbgModelTargetProcessImpl


class AbstractModelForDbgengScenarioMemoryTest(unittest.TestCase):

    def get_specimen(self):
        return "PRINT"

    def get_symbol_name(self):
        return "overwrite"

    def get_address_to_write(self, process):
        module_path = [process.get_path(), f"Modules[{self.get_specimen()}]"]
        container = process.find_container(TargetSymbol, *module_path)
        symbol = next((s for s in container.fetch_elements() if s.name == self.get_symbol_name()), None).as_target_symbol()
        return symbol.value

    def get_bytes_to_write(self):
        return "Speak".encode()

    def get_expected_bytes(self):
        return "Speak, World!".encode()

    def verify_expected_effect(self, process):
        while True:
            status = process.get_attribute_now(DbgModelTargetProcessImpl.EXIT_CODE_ATTRIBUTE_NAME, 0)
            self.assertEqual(status, 'S')
```

Please note that this is a direct translation of the Java code to Python. The equivalent classes and methods in Python are different from those in Java.