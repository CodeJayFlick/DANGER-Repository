import unittest
from ghidra.feature.vt.api.correlator.program import VTAbstractReferenceProgramCorrelatorFactory
from ghidra.feature.vt.api.main import *
from ghidra.feature.vt.gui.task import ApplyMatchTask

class VTDatapointCorrelator_x86_Test(unittest.TestCase):

    def setUp(self):
        self.test_correlator = "Data Reference Match"
        super(VTDatapointCorrelator_x86_Test, self).__init__()

    # Specify 3 known data matches referenced by the "print" functions, then run the Data Reference 
    # Correlator and test that only the print functions match
    def test_data_reference_correlator_only_print_data_matches(self):
        associations = []
        
        associations.append(VTAssociationPair(addr(src_prog, "00416830"), addr(dest_prog, "00416830"), VTAssociationType.DATA))
        associations.append(VTAssociationPair(addr(src_prog, "0041684c"), addr(dest_prog, "0041684c"), VTAssociationType.DATA))
        associations.append(VTAssociationPair(addr(src_prog, "00416858"), addr(dest_prog, "00416858"), VTAssociationType.DATA))

        match_set = create_match_set(session, associations)
        
        for match in match_set.get_matches():
            apply_match(match)

        run_test_correlator(self.test_correlator)

        vt_match_set = get_vt_match_set(self.test_correlator)
        self.assertIsNotNone(vt_match_set)

        test_match_pairs = get_match_address_pairs(vt_match_set)
        
        expected_match_pairs = set()
        expected_match_pairs.add(associate(addr(src_prog, "004115d0"), addr(dest_prog, "004115c0")))  # src: print

        assert_match_pairs(expected_match_pairs, test_match_pairs)

    # Run the Exact Data Match correlator and accept all matches, 
    # then run the Data Reference Correlator and test that the expected matches match and
    # that nothing else matches
    def test_data_reference_correlator_all_data_matches(self):
        run_test_correlator("Exact Data Match")

        for ms in session.get_match_sets():
            task = ApplyMatchTask(controller, list(ms.get_matches()))
            run_task(task)

        run_test_reference_correlatorWithOptions(self.test_correlator, 1.0,
                                                  VTAbstractReferenceProgramCorrelatorFactory.MEMORY_MODEL_DEFAULT, 
                                                  0.1, True)
        
        vt_match_set = get_vt_match_set(self.test_correlator)
        self.assertIsNotNone(vt_match_set)

        test_match_pairs = get_match_address_pairs(vt_match_set)
        
        expected_match_pairs = set()
        expected_match_pairs.add(associate(addr(src_prog, "004118f0"), addr(dest_prog, "004118c0")))  # src: deployGadget dst: FUN_004118c0
        expected_match_pairs.add(associate(addr(src_prog, "004115d0"), addr(dest_prog, "004115c0")))   # src: print dst: print
        expected_match_pairs.add(associate(addr(src_prog, "00411700"), addr(dest_prog, "004116f0")))  # src: addPeople dst: addPeople
        expected_match_pairs.add(associate(addr(src_prog, "00411f00"), addr(dest_prog, "00411ee0")));   # src: ___tmainCRTStartup dst: ___tmainCRTStartup -- similarity score < 0.5
        expected_match_pairs.add(associate(addr(src_prog, "004122b0"), addr(dest_prog, "00412290")));   # src: __RTC_GetErrDesc dst: __RTC_GetErrDesc
        expected_match_pairs.add(associate(addr(src_prog, "00412380"), addr(dest_prog, "00412360")));   # src: _RTC_ Failure dst:  _RTC_Failure
        expected_match_pairs.add(associate(addr(src_prog, "004123f0"), addr(dest_prog, "004123d0")));   # src: failwithmessage dst: failwithmessage
        expected_match_pairs.add(associate(addr(src_prog, "00412810"), addr(dest_prog, "004127f0")));   # src: _RTC_StackFailure dst:  _RTC_StackFailure
        expected_match_pairs.add(associate(addr(src_prog, "00412950"), addr(dest_prog, "00412930")));   # src: _RTC_AllocaFailure dst:  _RTC_AllocaFailure
        expected_match_pairs.add(associate(addr(src_prog, "00412ad0"), addr(dest_prog, "00412ab0")));   # src: _getMemBlockDataString dst:  _getMemBlockDataString
        expected_match_pairs.add(associate(addr(src_prog, "00412b60"), addr(dest_prog, "00412b40")));   # src: __RTC_UninitUse dst:  __RTC_UninitUse
        expected_match_pairs.add(associate(addr(src_prog, "00412e90"), addr(dest_prog, "00412e70")));   # src: __setdefaultprecision dst:  __setdefaultprecision
        expected_match_pairs.add(associate(addr(src_prog, "00413520"), addr(dest_prog, "00413500")));   # src: _RTC_GetSrcLine dst:  _RTC_GetSrcLine
        expected_match_pairs.add(associate(addr(src_prog, "00413890"), addr(dest_prog, "00413870")));   # src: GetPdbDll dst: GetPdbDll

        assert_match_pairs(expected_match_pairs, test_match_pairs)

if __name__ == '__main__':
    unittest.main()
