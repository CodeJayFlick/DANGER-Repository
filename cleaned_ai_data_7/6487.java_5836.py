import unittest
from ghidra_app.util.cparser import CParser
from ghidra.program.model.data import *
from ghidra.app.services import DataTypeManagerService
from ghidra.app.plugin.core.analysis import DefaultDataTypeManagerService
from ghidra.test import AbstractGhidraHeadedIntegrationTest

class FunctionSignatureParserTest(AbstractGhidraHeadedIntegrationTest):
    def setUp(self):
        program = ProgramBuilder("test", False).getProgram()
        s = StructureDataType("StructA", 0)
        s.setPackingEnabled(True)
        s.add(IntegerDataType.dataType)
        program.getDataTypeManager().addDataType(s, None)

        service = DefaultDataTypeManagerService()
        dtList = ArrayList() if not hasattr(ArrayList, 'from_list') else list(map(lambda x: x, []))
        super().__init__()
        self.parser = CParser(program.getDataTypeManager(), service)

    def testSubstitute(self):
        assertEquals("barxxxbar", self.parser.substitute("barfoobar", "foo", "xxx"))
        assertEquals("barxxx]bar", self.parser.substitute("bar[foo]bar", "[foo", "xxx"))

    # ... and so on for the rest of the tests

if __name__ == '__main__':
    unittest.main()
