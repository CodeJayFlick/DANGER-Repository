Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra_app_server import *

class EH32CreateCmdTest(unittest.TestCase):

    def setUp(self):
        self.builder = build32BitX86()
        self.program = self.builder.getProgram()

    def tearDown(self):
        preserveDTMService(self.program)
        if self.builder is not None:
            self.builder.dispose()
            self.builder = None

    @unittest.skip("Not implemented")
    def testValidV1FuncInfo32Cmd(self):
        setupV1FuncInfo32CompleteFlow(self.builder)
        assertEquals(self.builder.addr(0x01000000L), self.program.getImageBase())

        v1FuncInfoCmd = CreateEHFuncInfoBackgroundCmd(addr(self.program, 0x01003340),
            defaultValidationOptions, defaultApplyOptions)

        txID = self.program.startTransaction("Creating EH data")
        commit = False
        try:
            applied = v1FuncInfoCmd.applyTo(self.program)
            assertTrue(applied)
            commit = True
        finally:
            self.program.endTransaction(txID, commit)

        checkFuncInfoV1Data(self.program, 0x01003340L)

    @unittest.skip("Not implemented")
    def testValidV2FuncInfo32Cmd(self):
        setupV2FuncInfo32CompleteFlow(self.builder)
        assertEquals(self.builder.addr(0x01000000L), self.program.getImageBase())

        v2FuncInfoCmd = CreateEHFuncInfoBackgroundCmd(addr(self.program, 0x01003340),
            defaultValidationOptions, defaultApplyOptions)

        txID = self.program.startTransaction("Creating EH data")
        commit = False
        try:
            applied = v2FuncInfoCmd.applyTo(self.program)
            assertTrue(applied)
            commit = True
        finally:
            self.program.endTransaction(txID, commit)

        checkFuncInfoV2Data(self.program, 0x01003340L)

    @unittest.skip("Not implemented")
    def testValidUnwindMap32Cmd(self):
        setupUnwind32CompleteFlow(self.builder)
        assertEquals(self.builder.addr(0x01000000L), self.program.getImageBase())

        unwindMapCmd = CreateEHUnwindMapBackgroundCmd(addr(self.program, 0x01003368),
            defaultValidationOptions, defaultApplyOptions)

        txID = self.program.startTransaction("Creating EH data")
        commit = False
        try:
            applied = unwindMapCmd.applyTo(self.program)
            assertTrue(applied)
            commit = True
        finally:
            self.program.endTransaction(txID, commit)

        checkUnwindMapData32(self.program, 0x01003368)

    @unittest.skip("Not implemented")
    def testValidTryBlockMap32Cmd(self):
        setupTryBlock32CompleteFlow(self.builder)
        assertEquals(self.builder.addr(0x01000000L), self.program.getImageBase())

        tryBlockMapCmd = CreateEHTryBlockMapBackgroundCmd(addr(self.program, 0x01003380),
            defaultValidationOptions, defaultApplyOptions)

        txID = self.program.startTransaction("Creating EH data")
        commit = False
        try:
            applied = tryBlockMapCmd.applyTo(self.program)
            assertTrue(applied)
            commit = True
        finally:
            self.program.endTransaction(txID, commit)

        checkTryBlockData32(self.program, 0x01003380)

    @unittest.skip("Not implemented")
    def testValidCatchHandlerMap32Cmd(self):
        setupCatchHandler32CompleteFlow(self.builder)
        assertEquals(self.builder.addr(0x01000000L), self.program.getImageBase())

        catchHandlerMapCmd = CreateEHCatchHandlerMapBackgroundCmd(addr(self.program, 0x010033a8),
            defaultValidationOptions, defaultApplyOptions)

        txID = self.program.startTransaction("Creating EH data")
        commit = False
        try:
            applied = catchHandlerMapCmd.applyTo(self.program)
            assertTrue(applied)
            commit = True
        finally:
            self.program.endTransaction(txID, commit)

        checkCatchHandlerData32(self.program, 0x010033a8)

    @unittest.skip("Not implemented")
    def testValidTypeDescriptor32Cmd(self):
        setupV3FuncInfo32CompleteFlow(self.builder)
        assertEquals(self.builder.addr(0x01000000L), self.program.getImageBase())

        typeDescriptorCmd = CreateTypeDescriptorBackgroundCmd(addr(self.program, 0x01005400),
            defaultValidationOptions, defaultApplyOptions)

        txID = self.program.startTransaction("Creating EH data")
        commit = False
        try:
            applied = typeDescriptorCmd.applyTo(self.program)
            assertTrue(applied)
            commit = True
        finally:
            self.program.endTransaction(txID, commit)

        checkTypeDescriptorData(self.program, 0x01005400, 8, 20, "NotReachableError")

    @unittest.skip("Not implemented")
    def testValidIPToStateMap32Cmd(self):
        setupV3FuncInfo32CompleteFlow(self.builder)
        assertEquals(self.builder.addr(0x01000000L), self.program.getImageBase())

        ipToStateMapCmd = CreateEHIPToStateMapBackgroundCmd(addr(self.program, 0x010033d0),
            defaultValidationOptions, defaultApplyOptions)

        txID = self.program.startTransaction("Creating EH data")
        commit = False
        try:
            applied = ipToStateMapCmd.applyTo(self.program)
            assertTrue(applied)
            commit = True
        finally:
            self.program.endTransaction(txID, commit)

        checkIPToStateMapData32(self.program, 0x010033d0)

    @unittest.skip("Not implemented")
    def testValidESTypeList32Cmd(self):
        setupV3FuncInfo32CompleteFlow(self.builder)
        assertEquals(self.builder.addr(0x01000000L), self.program.getImageBase())

        esTypeListCmd = CreateEHESTypeListBackgroundCmd(addr(self.program, 0x010033f0),
            defaultValidationOptions, defaultApplyOptions)

        txID = self.program.startTransaction("Creating EH data")
        commit = False
        try:
            applied = esTypeListCmd.applyTo(self.program)
            assertTrue(applied)
            commit = True
        finally:
            self.program.endTransaction(txID, commit)

        checkESTypeListData32(self.program, 0x010033f0)

    @unittest.skip("Not implemented")
    def testValidV1FuncInfo32CmdNoFollow(self):
        setupV1FuncInfo32CompleteFlow(self.builder)
        assertEquals(self.builder.addr(0x01000000L), self.program.getImageBase())

        v1FuncInfoCmd = CreateEHFuncInfoBackgroundCmd(addr(self.program, 0x01001340),
            noFollowValidationOptions, noFollowApplyOptions)

        txID = self.program.startTransaction("Creating EH data")
        commit = False
        try:
            applied = v1FuncInfoCmd.applyTo(self.program)
            assertTrue(applied)
            commit = True
        finally:
            self.program.endTransaction(txID, commit)

        checkFuncInfoV1Data(self.program, 0x01001340L)

    @unittest.skip("Not implemented")
    def testValidV2FuncInfo32CmdNoFollow(self):
        setupV2FuncInfo32CompleteFlow(self.builder)
        assertEquals(self.builder.addr(0x01000000L), self.program.getImageBase())

        v2FuncInfoCmd = CreateEHFuncInfoBackgroundCmd(addr(self.program, 0x01001340),
            noFollowValidationOptions, noFollowApplyOptions)

        txID = self.program.startTransaction("Creating EH data")
        commit = False
        try:
            applied = v2FuncInfoCmd.applyTo(self.program)
            assertTrue(applied)
            commit = True
        finally:
            self.program.endTransaction(txID, commit)

        checkFuncInfoV2Data(self.program, 0x01001340L)

    @unittest.skip("Not implemented")
    def testValidUnwindMap32CmdNoFollow(self):
        setupUnwind32CompleteFlow(self.builder)
        assertEquals(self.builder.addr(0x01000000L), self.program.getImageBase())

        unwindMapCmd = CreateEHUnwindMapBackgroundCmd(addr(self.program, 0x01001320),
            noFollowValidationOptions, noFollowApplyOptions)

        txID = self.program.startTransaction("Creating EH data")
        commit = False
        try:
            applied = unwindMapCmd.applyTo(self.program)
            assertTrue(applied)
            commit = True
        finally:
            self.program.endTransaction(txID, commit)

        checkUnwindMapData32(self.program, 0x01001320L)

    @unittest.skip("Not implemented")
    def testValidTryBlockMap32CmdNoFollow(self):
        setupTryBlock32CompleteFlow(self.builder)
        assertEquals(self.builder.addr(0x01000000L), self.program.getImageBase())

        tryBlockMapCmd = CreateEHTryBlockMapBackgroundCmd(addr(self.program, 0x01001340),
            noFollowValidationOptions, noFollowApplyOptions)

        txID = self.program.startTransaction("Creating EH data")
        commit = False
        try:
            applied = tryBlockMapCmd.applyTo(self.program)
            assertTrue(applied)
            commit = True
        finally:
            self.program.endTransaction(txID, commit)

    @unittest.skip("Not implemented")
    def testValidCatchHandlerMap32CmdNoFollow(self):
        setupCatchHandler32CompleteFlow(self.builder)
        assertEquals(self.builder.addr(0x01000000L), self.program.getImageBase())

        catchHandlerMapCmd = CreateEHCatchHandlerMapBackgroundCmd(addr(self.program, 0x01001340),
            noFollowValidationOptions, noFollowApplyOptions)

    @unittest.skip("Not implemented")
    def testValidTypeDescriptor32CmdNoFollow(self):
        setupTypeList32CompleteFlow(self.builder)
        assertEquals(self.builder.addr(0x01000000L), self.program.getImageBase())

        typeDesc = CreateTypeDescriptorBackgroundCmd(addr(self.program, 0x01001340),
            noFollowValidationOptions, noFollowApplyOptions)

    @unittest.skip("Not implemented")
    def testValidESTypeList32CmdNoFollow(self):
        setupV1FuncInfo32CmdNoFollow(self):

    @unittest.skip("Not implemented")

    def testValidTypeDescriptorBackgroundCmd(addr(self.program, 0x01001340),
            noFollowValidationOptions,
            noFollowApplyOptions

    @unittest.skip("Not implemented")
    def testESTypeList32CmdNoFollow(self):
        setupV1FuncInfo32CmdNoFollow(self):

    @unittest.skip("Not implemented")

    def testValidTypeDescriptorBackgroundCmd(addr(self.program, 0x01001340),
            noFollowValidationOptions,
            noApplyOptions

    def testValidESTypeList32CmdNoFollow(self):
        setValidESTypeList32CmdNoFollow(self):