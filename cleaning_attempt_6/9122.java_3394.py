import unittest
from ghidra.feature.vt.api.main import VTMatchSet
from ghidra.feature.vt.api.impl import VTProgramCorrelatorInfo
from ghidra.feature.vt.db import VTSessionDB


class TestVTSessionDB(unittest.TestCase):

    def setUp(self):
        self.test_transaction_id = db.start_transaction("Test")

    def tearDown(self):
        db.end_transaction(self.test_transaction_id, False)

    @unittest.skipIf(not hasattr(db, 'create_match_set'), "db.create_match_set is not available")
    def test_create_get_match_set(self):
        correlator = VTProgramCorrelatorInfo()
        match_set = db.create_match_set(correlator)
        self.assertIsNotNone(match_set)

        match_sets = db.get_match_sets()
        self.assertEqual(3, len(match_sets))
        self.assertEqual(match_set, match_sets[2])

    @unittest.skipIf(not hasattr(db, 'create_program_correlator'), "db.create_program_correlator is not available")
    def test_create_get_program_correlator(self):
        # This method allows us to test that we can create/ save/and restore version tracking managers...it takes a while, so we don't wanna do it all the time...plus this code is ultimately tested during usage...we did it here for TDD purposes.
        pass

    @unittest.skipIf(not hasattr(db, 'get_name'), "db.get_name is not available")
    def test_get_name(self):
        self.assertEqual("Untitled", db.get_name())

        # GhidraProject project = GhidraProject.create_project(  "C:\\Temp\\",  "GhidrProject", true );
        # DomainFolder rootFolder = project.getRootFolder();
        # DomainFile file = rootFolder.createFile(  "foop", db, TaskMonitorAdapter.DUMMY_MONITOR );

        source_program = db.get_source_program()
        destination_program = db.get_destination_program()

        # db.close();

        domain_object = None
        # assertTrue(domainObject instanceof VTSessionDB);
        # assertEquals("foop", domainObject.getName());

        # db = (VTSessionDB)domainObject;

        unrelated_program = None  # createProgram( "TEST" );
        try:
            db.set_programs(unrelated_program, unrelated_program)
            self.fail("Should not have been able to set the wrong program")
        except Exception as e:
            pass

        db.set_programs(source_program, destination_program)

        test_transaction_id = db.start_transaction("Test")  # for cleanup
