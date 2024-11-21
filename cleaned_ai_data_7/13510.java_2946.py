import unittest
from ghidra_app_script import GhidraAppScript
from ghidra_framework import Application
from ghidra_program_model_address import Address
from ghidra_program_model_listing import Listing
from ghidra_program_model_symbol_ref_type import RefType

class WindowsResourceReferenceScriptTest(unittest.TestCase):

    def setUp(self):
        self.env = GhidraAppScript()
        script_file = self.env.get_module_file("Decompiler", "ghidra_scripts/WindowsResourceReference.py")
        self.script = script_file.get_file(True)

    def open_program(self, program):
        pm = self.env.get_tool().get_service(Application.ProgramManager)
        pm.open_program(program.get_domain_file())

    def close_program(self):
        pm = self.env.get_tool().get_service(Application.ProgramManager)
        pm.close_program()
        import time
        time.sleep(1)

    @classmethod
    def tearDownClass(cls):
        cls.env.dispose()

    def test_winmine_normal_cases(self):
        refs = []
        type = None
        is_addr = False
        inst = None

        program = self.env.get_program("Winmine__XP.exe.gzf")
        self.open_program(program)

        script_id = self.env.run_script(self.script)
        import time
        time.sleep(65)  # wait for the script to complete
        program.flush_events()
        import time
        time.sleep(1)

        listing = program.get_listing()

        winmine_test_addrs = [self.addr(0x01001b99, program), self.addr(0x01001bc2, program),
                              self.addr(0x01001b5e, program), self.addr(0x010022c2, program),
                              self.addr(0x01002243, program), self.addr(0x01003d52, program),
                              self.addr(0x010022ac, program), self.addr(0x01002334, program),
                              self.addr(0x01001f3b, program), self.addr(0x0100398f, program),
                              self.addr(0x01003ade, program), self.addr(0x01003aec, program),
                              self.addr(0x01003ad0, program), self.addr(0x010039c5, program),
                              self.addr(0x01003d45, program), self.addr(0x0100385b, program),
                              self.addr(0x01003d36, program), self.addr(0x01003920, program)]

        for winmine_test_addr in winmine_test_addrs:
            inst = listing.get_instruction_at(winmine_test_addr)
            refs = inst.get_mnemonic_references()
            assert refs is not None
            type = refs[0].get_reference_type()
            is_addr = refs[0].get_to_address().is_memory_address()
            self.assertTrue(is_addr)
            self.assertEqual(type, RefType.DATA)

        self.close_program()

    def test_mip_normal_cases(self):
        refs = []
        type = None
        is_addr = False
        inst = None

        program = self.env.get_program("mip.exe.gzf")
        self.open_program(program)

        script_id = self.env.run_script(self.script)
        import time
        time.sleep(60)  # wait for the script to complete
        program.flush_events()
        import time
        time.sleep(1)

        listing = program.get_listing()

        mip_test_addrs = [self.addr(0x1400172c7, program), self.addr(0x14005282d, program),
                          self.addr(0x14005276c, program), self.addr(0x1400523ba, program),
                          self.addr(0x14004ca38, program), self.addr(0x14003d855, program),
                          self.addr(0x14001a964, program), self.addr(0x14001846f, program),
                          self.addr(0x140025c87, program)]

        for mip_test_addr in mip_test_addrs:
            inst = listing.get_instruction_at(mip_test_addr)
            refs = inst.get_mnemonic_references()
            assert refs is not None
            type = refs[0].get_reference_type()
            is_addr = refs[0].get_to_address().is_memory_address()
            self.assertTrue(is_addr)
            self.assertEqual(type, RefType.DATA)

        self.close_program()

    def addr(self, offset, program):
        return Address(program.get_address_factory().default_address_space(), offset)

if __name__ == '__main__':
    unittest.main()
