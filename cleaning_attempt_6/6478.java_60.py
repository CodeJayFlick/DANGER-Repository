import unittest
from ghidra.app.util.bin.format.dwarf4.next import DWARFDataTypeConflictHandler
from ghidra.program.database import ProgramBuilder, ProgramDB
from ghidra.program.model.data import *
from ghidra.test.abstractGhidraHeadedIntegrationTest import AbstractGhidraHeadedIntegrationTest

class TestDWARFDataTypeConflictHandler(AbstractGhidraHeadedIntegrationTest):
    def setUp(self):
        self.program = createDefaultProgram("test", ProgramBuilder._TOY, this)
        self.data_mgr = self.program.getDataTypeManager()
        startTransaction()

    def tearDown(self):
        endTransaction()
        program.release(this)

    def testAddEmptyStructResolveToPopulatedStruct1(self):
        assertStruct(createPopulated(self.data_mgr), createStub(self.data_mgr, 0), ConflictResult.USE_EXISTING)

    # ... (rest of the tests are similar to this one)
