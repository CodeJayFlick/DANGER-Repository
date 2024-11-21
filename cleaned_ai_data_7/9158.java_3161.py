import unittest
from ghidra.feature.vt.api.main import VTMatchSet
from ghidra.feature.vt.gui.task import ApplyMatchTask


class TestVTFunctionReferenceCorrelatorELF(unittest.TestCase):

    def setUp(self):
        self.test_correlator = "Function Reference Match"
        super().__init__()

    # Specify only function matches referenced by single function, then run the Function 
    # Reference Correlator and make sure it matches only on functions that have those function references
    @unittest.skip("Not implemented yet")
    def test_function_reference_correlator_only_bob_function_matches(self):
        associations = []

        external_addr_for_src_prog = "sprintf"
        external_addr_for_dest_prog = "sprintf"
        associations.append((external_addr_for_src_prog, external_addr_for_dest_prog))

        external_addr_for_src_prog = "printf"
        external_addr_for_dest_prog = "printf"
        associations.append((external_addr_for_src_prog, external_addr_for_dest_prob))

        external_addr_for_src_prog = "fprintf"
        external_addr_for_dest_prog = "fprintf"
        associations.append((external_addr_for_src_prog, external_addr_for_dest_prog))

        match_set = create_match_set(associations)
        matches = match_set.get_matches()
        for match in matches:
            apply_match(match)

        run_test_correlator(self.test_correlator)

        vt_match_set = get_vt_match_set(self.test_correlator)
        self.assertIsNotNone(vt_match_set, "vtMatchSet does not exist")

        test_matches = get_match_address_pairs(vt_match_set)
        expected_matches = set()
        expected_matches.add((addr(src_prog, "0040063e"), addr(dest_prog, "080484ca")))
        assert_match_pairs(expected_matches, test_matches)

    # Run the Exact Function Match correlator and accept all matches, 
    # then run the Function Reference Correlator and test that only expected matches are found
    @unittest.skip("Not implemented yet")
    def test_function_reference_correlator_all_function_matches(self):
        exact_symbol_name_correlator = "Exact Symbol Name Match"
        run_test_correlator(exact_symbol_name_correlator)

        apply_match_task(task, (list(match_set.get_matches())))

        run_test_correlator(self.test_correlator)

        vt_match_set = get_vt_match_set(self.test_correlator)
        self.assertIsNotNone(vt_match_set, "vtMatchSet does not exist")

        test_match_pairs = get_match_address_pairs(vt_match_set)
        expected_match_pairs = set()
        expected_match_pairs.add((addr(src_prog, "00400938"), addr(dest_prog, "0804874c")))
        expected_match_pairs.add((addr(src_prog, "00400870"), addr(dest_prob, "080486c0")))
        expected_match_pairs.add((addr(src_prog, "004004b0"), addr(dest_prog, "08048334")))
        expected_match_pairs.add((addr(src_prog, "0040079c"), addr(dest_prog, "080485f3")))
        expected_match_pairs.add((addr(src_prog, "00400540"), addr(dest_prob, "080483f0")))
        expected_match_pairs.add((addr(src_prog, "0040063e"), addr(dest_prog, "080484ca")))

        assert_match_pairs(expected_match_pairs, test_match_pairs)


if __name__ == '__main__':
    unittest.main()
