import unittest
from ghidra_framework import *

class VTDuplicateSymbolMatchTest(unittest.TestCase):
    def setUp(self):
        self.env = VTTestEnv()
        tool = self.env.show_tool()
        session = self.env.create_session("VersionTracking/WallaceSrc.dupeStringTest.gzf", "VersionTracking/WallaceVersion2", DuplicateSymbolNameProgramCorrelatorFactory())
        assert session is not None

        src_prog = self.env.get_source_program()
        dest_prog = self.env.get_destination_program()

    def tearDown(self):
        self.env.dispose()

    def test_duplicate_symbol_correlator(self):
        match_sets = session.get_match_sets()
        self.assertEqual(3, len(match_sets))

        # Make sure these are found by the duplicate symbol matcher:
        self.assertTrue(is_match(addr(src_prog, "00417060"), addr(dest_prog, "00417060")))
        self.assertTrue(is_match(addr(src_prog, "00417060"), addr(dest_prog, "00416fd8")))
        self.assertTrue(is_match(addr(src_prog, "00416fd8"), addr(dest_prog, "00417060")))
        self.assertTrue(is_match(addr(src_prog, "00416fd8"), addr(dest_prog, "00416fd8")))

        # Make sure these are not found by the duplicate matcher (should be found by unique matcher)
        self.assertFalse(is_match(addr(src_prog, "00419284"), addr(dest_prog, "00419280")))
        self.assertFalse(is_match(addr(src_prog, "00419288"), addr(dest_prog, "00419280")))
        self.assertFalse(is_match(addr(src_prog, "00419284"), addr(dest_prog, "00419284")))
        self.assertFalse(is_match(addr(src_prog, "00419288"), addr(dest_prog, "00419284")))

    def is_match(self, src_addr, dest_addr):
        match_sets = session.get_match_sets()
        for i in range(len(match_sets)):
            if len(match_sets[i].get_matches(src_addr, dest_addr)) > 0:
                return True
        return False

    def addr(self, program, address):
        return program.getAddressFactory().getAddress(address)

if __name__ == '__main__':
    unittest.main()
