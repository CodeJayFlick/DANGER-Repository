Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra_app.util.bin.format.dwarf4 import DWARFAttributeFactory
from ghidra_app.util.bin.format.dwarf4.attribs import DIECreator
from ghidra_app.util.bin.format.dwarf4.encoding import *
from ghidra_program.model.listing import Program

class DIETest(unittest.TestCase):

    def setUp(self):
        self.prog = DWARFProgram(Program("Test", True), DWARFImportOptions(), TaskMonitor.DUMMY, NullSectionProvider())
        self.attribFactory = self.prog.getAttributeFactory()
        self.cu = MockDWARFCompilationUnit(self.prog, 0x1000, 0x2000, 0, DWARFCU.DWARF_32, (short)4, 0, (byte)8, 0, DWSourceLanguage.DW_LANG_C)

    def test_DIEAggregate(self):
        declStruct = DIECreator(DWARFTag.DW_TAG_structure_type).addString(DWARFAttribute.DW_AT_name, "mystruct").addBoolean(DWARFAttribute.DW_AT_declaration, True).addString(DWARFAttribute.DW_AT_const_value, "declConst").addString(DWARFAttribute.DW_AT_description, "declDesc").create(self.cu)
        implStruct = DIECreator(DWARFTag.DW_TAG_structure_type).addString(DWARFAttribute.DW_AT_name, "mystruct").addRef(DWARFAttribute.DW_AT_specification, declStruct).addString(DWARFAttribute.DW_AT_const_value, "specConst").addString(DWARFAttribute.DW_AT_description, "declDesc").create(self.cu)
        aoStruct = DIECreator(DWARFTag.DW_TAG_structure_type).addString(DWARFAttribute.DW_AT_name, "mystruct").addRef(DWARFAttribute.DW_AT_abstract_origin, implStruct).addString(DWARFAttribute.DW_AT_description, "aoDesc").create(self.cu)

        self.prog.checkPreconditions(TaskMonitor.DUMMY)
        self.prog.setCurrentCompilationUnit(self.cu, TaskMonitor.DUMMY)

        struct_via_ao = self.prog.getAggregate(aoStruct)

        self.assertEqual("MyStruct aggregate should have 3 fragments", 3, len(struct_via_ao.offsets))
        self.assertEqual("Attr dw_at_const should be from spec", "specConst", struct_via_ao.getString(DWARFAttribute.DW_AT_const_value, None))
        self.assertEqual("Attr dw_at_description should be from ao", "aoDesc", struct_via_ao.getString(DWARFAttribute.DW_AT_description, None))

    def test_DIEAggregateMulti(self):
        declStruct = DIECreator(DWARFTag.DW_TAG_structure_type).addString(DWARFAttribute.DW_AT_name, "mystruct").addBoolean(DWARFAttribute.DW_AT_declaration, True).addString(DWARFAttribute.DW_AT_const_value, "declConst").addString(DWARFAttribute.DW_AT_description, "declDesc").create(self.cu)
        implStruct = DIECreator(DWARFTag.DW_TAG_structure_type).addString(DWARFAttribute.DW_AT_name, "mystruct").addRef(DWARFAttribute.DW_AT_specification, declStruct).addString(DWARFAttribute.DW_AT_const_value, "specConst").addString(DWARFAttribute.DW_AT_description, "declDesc").create(self.cu)
        ao1Struct = DIECreator(DWARFTag.DW_TAG_structure_type).addString(DWARFAttribute.DW_AT_name, "mystruct").addRef(DWARFAttribute.DW_AT_abstract_origin, implStruct).addString(DWARFAttribute.DW_AT_description, "ao1Desc").create(self.cu)
        ao2Struct = DIECreator(DWARFTag.DW_TAG_structure_type).addString(DWARFAttribute.DW_AT_name, "mystruct").addRef(DWARFAttribute.DW_AT_abstract_origin, implStruct).addString(DWARFAttribute.DW_AT_description, "ao2Desc").create(self.cu)

        self.prog.checkPreconditions(TaskMonitor.DUMMY)
        self.prog.setCurrentCompilationUnit(self.cu, TaskMonitor.DUMMY)

        ao1 = self.prog.getAggregate(ao1Struct)
        ao2 = self.prog.getAggregate(ao2Struct)

        self.assertEqual("Should have 3 fragments", 3, len(ao1.offsets))
        self.assertEqual("Should have 3 fragments", 3, len(ao2.offsets))
        self.assertEqual("Attr dw_at_const should be from spec", "specConst", ao1.getString(DWARFAttribute.DW_AT_const_value, None))
        self.assertEqual("Attr dw_at_const should be from spec", "specConst", ao2.getString(DWARFAttribute.DW_AT_const_value, None))
        self.assertEqual("Attr dw_at_description should be from ao1", "ao1Desc", ao1.getString(DWARFAttribute.DW_AT_description, None))
        self.assertEqual("Attr dw_at_description should be from ao2", "ao2Desc", ao2.getString(DWARFAttribute.DW_AT_description, None))

    def test_PagedEntryChecking(self):
        die1 = DIECreator(DWARFTag.DW_TAG_base_type).create(self.cu)

        try:
            self.prog.getAggregate(die1)
            assert False
        except Exception as e:
            pass

        self.prog.setCurrentCompilationUnit(self.cu, TaskMonitor.DUMMY)
        struct_via_ao = self.prog.getAggregate(die1)
        assert struct_via_ao is not None


if __name__ == '__main__':
    unittest.main()
```

Please note that this code assumes you have the necessary modules and classes available.