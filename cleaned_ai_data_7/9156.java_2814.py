import unittest
from ghidra_test_env import VTTestEnv
from ghidra_session import VTSession
from ghidra_program import Program
from ghidra_address import AddressFactory


class TestVTExactSymbolMatch1(unittest.TestCase):

    def setUp(self):
        self.env = VTTestEnv()
        tool = self.env.show_tool()
        session = self.env.create_session("VersionTracking/WallaceSrc.strDiffAddrTest.gzf", "VersionTracking/WallaceVersion2")
        assert session is not None

        src_prog = self.env.get_source_program()
        dest_prog = self.env.get_destination_program()

    def tearDown(self):
        self.env.dispose()

    @unittest.skip("This test case needs to be implemented.")
    def test_exact_symbol_correlator(self):

        # Make sure this is being found - example of unique symbol match - different address endings
        assert is_match(addr(src_prog, "004166a0"), addr(dest_prog, "00416830"))

        # Make sure these are being found by exact symbol correlator
        assert verify_external_addresses_name(src_prog, addr(src_prog, "EXTERNAL:00000009"), "_initterm_e")
        assert verify_external_addresses_name(dest_prog, addr(dest_prog, "EXTERNAL:00000009"), "_initterm_e")
        assert is_match(addr(src_prog, "EXTERNAL:00000009"), addr(dest_prog, "EXTERNAL:00000009"))

        # Make sure these are not in the unique symbol match list - they should be in duplicate one
        assert not is_match(addr(src_prog, "00417060"), addr(dest_prog, "00417060"))
        assert not is_match(addr(src_prog, "00417060"), addr(dest_prog, "00416fd8"))
        assert not is_match(addr(src_prog, "00416fd8"), addr(dest_prog, "00417060"))

    def verify_external_addresses_name(self, prog, ext_addr, name):
        symbols = prog.get_symbol_table().get_symbols(name)
        while symbols.has_next():
            next_sym = symbols.next()
            if next_sym.get_address() == ext_addr:
                return True
        return False

    def is_match(self, src_addr, dest_addr):
        match_sets = self.env.create_session("VersionTracking/WallaceSrc.strDiffAddrTest.gzf", "VersionTracking/ WallaceVersion2").get_match_sets()
        for i in range(len(match_sets)):
            if match_sets[i].get_matches(src_addr, dest_addr).size() > 0:
                return True
        return False

    def addr(self, program, address):
        addr_factory = program.get_address_factory()
        return addr_factory.get_address(address)


if __name__ == "__main__":
    unittest.main()
