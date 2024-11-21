Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra_app_server import *

class EH64CreateCmdTest(unittest.TestCase):

    def setUp(self):
        self.builder = build64BitX86()
        self.program = self.builder.getProgram()

    def tearDown(self):
        if self.builder is not None:
            self.builder.dispose()
            self.builder = None

    @unittest.skip("Not implemented")
    def testValidV1FuncInfo64Cmd(self):
        setupV1FuncInfo64CompleteFlow(self.builder)
        assertEquals(self.builder.addr(0x101000000L), self.program.getImageBase())

        v1FuncInfoCmd = CreateEHFuncInfoBackgroundCmd(addr(self.program, 0x101003340L),
            defaultValidationOptions, defaultApplyOptions)

        txID = self.program.startTransaction("Creating EH data")
        commit = False
        try:
            applied = v1FuncInfoCmd.applyTo(self.program)
            assertTrue(applied)
            commit = True
        finally:
            self.program.endTransaction(txID, commit)

        checkFuncInfoV1Data64(self.program, 0x101003340L)

    @unittest.skip("Not implemented")
    def testValidV2FuncInfo64Cmd(self):
        setupV2FuncInfo64CompleteFlow(self.builder)
        assertEquals(self.builder.addr(0x101000000L), self.program.getImageBase())

        v2FuncInfoCmd = CreateEHFuncInfoBackgroundCmd(addr(self.program, 0x101003340L),
            defaultValidationOptions, defaultApplyOptions)

        txID = self.program.startTransaction("Creating EH data")
        commit = False
        try:
            applied = v2FuncInfoCmd.applyTo(self.program)
            assertTrue(applied)
            commit = True
        finally:
            self.program.endTransaction(txID, commit)

        checkFuncInfoV2Data64(self.program, 0x101003340L)

    @unittest.skip("Not implemented")
    def testValidUnwindMap64Cmd(self):
        setupUnwind64CompleteFlow(self.builder)
        assertEquals(self.builder.addr(0x101000000L), self.program.getImageBase())

        unwindMapCmd = CreateEHUnwindMapBackgroundCmd(addr(self.program, 0x101003368L),
            defaultValidationOptions, defaultApplyOptions)

        txID = self.program.startTransaction("Creating EH data")
        commit = False
        try:
            applied = unwindMapCmd.applyTo(self.program)
            assertTrue(applied)
            commit = True
        finally:
            self.program.endTransaction(txID, commit)

        checkUnwindMapData64(self.program, 0x101003368L)

    @unittest.skip("Not implemented")
    def testValidTryBlockMap64Cmd(self):
        setupTryBlock64CompleteFlow(self.builder)
        assertEquals(self.builder.addr(0x101000000L), self.program.getImageBase())

        tryBlockMapCmd = CreateEHTryBlockMapBackgroundCmd(addr(self.program, 0x101003380L),
            defaultValidationOptions, defaultApplyOptions)

        txID = self.program.startTransaction("Creating EH data")
        commit = False
        try:
            applied = tryBlockMapCmd.applyTo(self.program)
            assertTrue(applied)
            commit = True
        finally:
            self.program.endTransaction(txID, commit)

        checkTryBlockData64(self.program, 0x101003380L)

    @unittest.skip("Not implemented")
    def testValidCatchHandlerMap64Cmd(self):
        setupCatchHandler64CompleteFlow(self.builder)
        assertEquals(self.builder.addr(0x101000000L), self.program.getImageBase())

        catchHandlerMapCmd = CreateEHCatchHandlerMapBackgroundCmd(addr(self.program, 0x1010033a8L),
            defaultValidationOptions, defaultApplyOptions)

        txID = self.program.startTransaction("Creating EH data")
        commit = False
        try:
            applied = catchHandlerMapCmd.applyTo(self.program)
            assertTrue(applied)
            commit = True
        finally:
            self.program.endTransaction(txID, commit)

        checkCatchHandlerData64(self.program, 0x1010033a8L)

    @unittest.skip("Not implemented")
    def testValidTypeDescriptor64Cmd(self):
        setupTypeList64CompleteFlow(self.builder)
        assertEquals(self.builder.addr(0x101000000L), self.program.getImageBase())

        typeDescriptorCmd = CreateTypeDescriptorBackgroundCmd(addr(self.program, 0x101005400L),
            defaultValidationOptions, defaultApplyOptions)

        txID = self.program.startTransaction("Creating EH data")
        commit = False
        try:
            applied = typeDescriptorCmd.applyTo(self.program)
            assertTrue(applied)
            commit = True
        finally:
            self.program.endTransaction(txID, commit)

        checkTypeDescriptorData64(self.program, 0x101005400L, 16, 24, "NotReachableError")

    @unittest.skip("Not implemented")
    def testValidIPToStateMap64Cmd(self):
        setupIPToState64CompleteFlow(self.builder)
        assertEquals(self.builder.addr(0x101000000L), self.program.getImageBase())

        ipToStateMapCmd = CreateEHIPToStateMapBackgroundCmd(addr(self.program, 0x1010033d0L),
            defaultValidationOptions, defaultApplyOptions)

        txID = self.program.startTransaction("Creating EH data")
        commit = False
        try:
            applied = ipToStateMapCmd.applyTo(self.program)
            assertTrue(applied)
            commit = True
        finally:
            self.program.endTransaction(txID, commit)

        checkIPToStateMapData64(self.program, 0x1010033d0L)

    @unittest.skip("Not implemented")
    def testValidESTypeList64Cmd(self):
        setupTypeList64CompleteFlow(self.builder)
        assertEquals(self.builder.addr(0x101000000L), self.program.getImageBase())

        esTypeListCmd = CreateEHESTypeListBackgroundCmd(addr(self.program, 0x1010033f0L),
            defaultValidationOptions, defaultApplyOptions)

        txID = self.program.startTransaction("Creating EH data")
        commit = False
        try:
            applied = esTypeListCmd.applyTo(self.program)
            assertTrue(applied)
            commit = True
        finally:
            self.program.endTransaction(txID, commit)

        checkESTypeListData64(self.program, 0x1010033f0L)

    @unittest.skip("Not implemented")
    def testValidV1FuncInfo64CmdNoFollow(self):
        setupV1FuncInfo64CompleteFlow(self.builder)
        assertEquals(self.builder.addr(0x101000000L), self.program.getImageBase())

        v1FuncInfoCmd = CreateEHFuncInfoBackgroundCmd(addr(self.program, 0x101003340L),
            noFollowValidationOptions, noFollowApplyOptions)

        txID = self.program.startTransaction("Creating EH data")
        commit = False
        try:
            applied = v1FuncInfoCmd.applyTo(self.program)
            assertTrue(applied)
            commit = True
        finally:
            self.program.endTransaction(txID, commit)

        checkFuncInfoV1Data64(self.program, 0x101003340L)

    @unittest.skip("Not implemented")
    def testValidV2FuncInfo64CmdNoFollow(self):
        setupV2FuncInfo64CompleteFlow(self.builder)
        assertEquals(self.builder.addr(0x101000000L), self.program.getImageBase())

        v2FuncInfoCmd = CreateEHFuncInfoBackgroundCmd(addr(self.program, 0x101003340L),
            noFollowValidationOptions, noFollowApplyOptions)

        txID = self.program.startTransaction("Creating EH data")
        commit = False
        try:
            applied = v2FuncInfoCmd.applyTo(self.program)
            assertTrue(applied)
            commit = True
        finally:
            self.program.endTransaction(txID, commit)

        checkFuncInfoV2Data64(self.program, 0x101003340L)

    @unittest.skip("Not implemented")
    def testValidUnwindMap64CmdNoFollow(self):
        setupUnwind64CompleteFlow(self.builder)
        assertEquals(self.builder.addr(0x10100000000), self.program.getImageBase())

        unwindMapCmd = CreateEHUnwindMapBackgroundCmd(addr(self.program, 0x01001640),
            noFollowValidationOptions, noFollowApplyOptions)

        txID = self.program.startTransaction("Creating EH data")
        commit = False
        try:
            applied = unwindMapCmd.applyTo(self.program)
            assertTrue(applied)
            commit = True
        finally:
            self.program.endTransaction(txID, commit)

    @unittest.skip("Not implemented")
    def testValidTryBlockMap64CmdNoFollow(self):
        setupTryBlockMapCompleteFlow(self.builder)
        assertEquals(self.builder.addr(0x10100000000), self.program.getImageBase())

        tryBlockMapCmd = CreateEHTryBlockMapBackgroundCmd(addr(self.program, 0x01001340),
            noFollowValidationOptions, noFollowApplyOptions)

        txID = self.program.startTransaction("Creating EH data")
        commit = False
        try:
            applied = unwindMapCmd.applyTo(self.program)
            assertTrue(applied)
            commit = True
        finally:
            program.endTransaction(txID, commit);