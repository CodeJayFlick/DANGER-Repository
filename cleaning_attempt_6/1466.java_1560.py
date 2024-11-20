import unittest
from ghidra import dbg, program, model, address

class AbstractModelForGdbScenarioMemoryTest(unittest.TestCase):

    def get_specimen(self):
        return "PRINT"

    def get_bin_module_name(self):
        return self.get_specimen()

    def get_symbol_name(self):
        return "overwrite"

    def get_address_to_write(self, process):
        module_path = [process.path] + ["Modules[" + self.get_bin_module_name() + "]"]
        container = next((container for container in process.find_containers(TargetSymbol) if PathUtils.extend(module_path)), None)
        symbol = next((symbol for symbol in container.fetch_symbols() if symbol.name == self.get_symbol_name()), None).as_target_symbol()
        return symbol.value

    def get_bytes_to_write(self):
        return "Speak".encode()

    def get_expected_bytes(self):
        return "Speak, World!".encode()

    def verify_expected_effect(self, process):
        status = process.get_attribute("EXIT_CODE", 0)
        self.assertEqual(b'S', status)

if __name__ == "__main__":
    unittest.main()
