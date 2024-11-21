Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra.app.decompiler.component import ClangTextField
from ghidra.framework.options import Options
from ghidra.program.database import ProgramCompilerSpec
from ghidra.program.model.address import Address
from ghidra.program.model.lang import *
from ghidra.util.exception import CancelledException, InvalidInputException

class SpecExtensionTest(unittest.TestCase):
    def test_BadCallotherTarget(self):
        myfixup = "<callotherfixup targetop=\"unknownop\">\n" \
                  "  <pcode>\n" \
                  "   <input name=\"fcx\"/>\n" \
                  "   <body><![CDATA[\n" \
                  "    EAX  = fcx + 2;\n" \
                  "  ]]></body>\n" \
                  "</pcode>\n" \
                  "</callotherfixup>\n"
        err_message = None
        try:
            spec_extension = SpecExtension(program)
            spec_extension.add_replace_compiler_spec_extension(myfixup, TaskMonitor.DUMMY)
            self.fail("expected exception")
        except (SleighException, XmlParseException, SAXException, LockException) as ex:
            err_message = ex.getMessage()
        self.assertTrue(err_message.find("CALLOTHER_FIXUP target does not exist") != -1)

    def test_BadExtension(self):
        myfixup = "<callfixup name=\"mynewthing\">\n" \
                  "   <target name=\"targ1\"/>\n" \
                  "   <pcode>\n" \
                  "     <body><![CDATA[\n" \
                  "     *ESP  = 1000:4;\n" \
                  "    ESP  = blahhh - 4;\n" \
                  "     ]]></body>\n" \
                  "</pcode>\n" \
                  "</callfixup>\n"
        err_message = None
        try:
            spec_extension.add_replace_compiler_spec_extension(myfixup, TaskMonitor.DUMMY)
        except (SleighException, XmlParseException, SAXException, LockException) as ex:
            err_message = ex.getMessage()
        self.assertTrue(err_message.find("halting compilation") != -1)

    def test_ExtensionNameCollision(self):
        myfixup = "<callfixup name=\"alloca_probe\"><pcode><body>ESP  = ESP - 4;</body></pcode></callfixup>"
        err_message = None
        try:
            spec_extension.add_replace_compiler_spec_extension(myfixup, TaskMonitor.DUMMY)
            self.fail("expected exception")
        except (SleighException, XmlParseException, SAXException, LockException) as ex:
            err_message = ex.getMessage()
        self.assertTrue(err_message.find("Extension cannot replace") != -1)

    def test_PrototypeExtension(self):
        decompile("100272e")
        line = get_line_containing("FUN_010026a7(pHVar1);")
        assert line is not None
        cspec = program.get_compiler_spec()
        default_model = cspec.get_default_calling_convention()
        buffer = StringBuilder()
        default_model.save_xml(buffer, cspec.get_pcode_inject_library())
        default_string = str(buffer)
        # Replace the output register EAX with ECX
        default_string = default_string.replace("<addr space=\"register\" offset=\"0x0\"/>", "<addr space=\"register\" offset=\"4\"/>")
        default_string = default_string.replace("piece2=\"register:0x0:4\"", "piece2=\"register:0x4:4\"")
        # Change the name
        default_string = default_string.replace("name=\"__stdcall\"", "name=\"myproto\"")

        spec_extension = SpecExtension(program)
        id1 = program.start_transaction("Test prototype install")
        try:
            spec_extension.add_replace_compiler_spec_extension(default_string, TaskMonitor.DUMMY)
        except (LockException, SleighException, SAXException, XmlParseException) as ex:
            self.fail(f"Unexpected exception: {ex.getMessage()}")
        program.end_transaction(id1, True)

        myproto = cspec.get_calling_convention("myproto")
        assert myproto is not None

        id = program.start_transaction("test extension install")
        addr = Address(program.getAddressFactory().getDefaultAddressSpace(), 0x100112c)
        func = program.getFunctionManager().getReferencedFunction(addr)
        change_works = True
        try:
            func.set_calling_convention("myproto")
        except InvalidInputException as e:
            change_works = False

        program.end_transaction(id, True)

        self.assertTrue(change_works)

        decompile("100272e")

        line = get_line_containing("FUN_010026a7(in_EAX);")
        assert line is not None

        id3 = program.start_transaction("Change eval model")
        options = Options(program.getOptions(ProgramCompilerSpec.DECOMPILER_PROPERTY_LIST_NAME))
        options.set_string(ProgramCompilerSpec.EVALUATION_MODEL_PROPERTY_NAME, "myproto")

        program.end_transaction(id3, True)

        eval_model = cspec.get_prototype_evaluation_model(EvaluationModelType.EVAL_CURRENT)
        res = ParamList.WithSlotRec()
        ecx_addr = Address(program.getAddressFactory().getRegisterSpace(), 4)
        out_exists = eval_model.possible_output_param_with_slot(ecx_addr, 4, res)

        self.assertTrue(out_exists)

        id2 = program.start_transaction("test extension removal")
        try:
            spec_extension.remove_compiler_spec_extension("prototype_myproto", TaskMonitor.DUMMY)
        except (LockException, CancelledException) as ex:
            self.fail(f"Unexpected exception: {ex.getMessage()}")
        program.end_transaction(id2, True)

        myproto = cspec.get_calling_convention("myproto")
        assert myproto is None
        func.set_calling_convention_name("__stdcall")
        eval_model = cspec.get_prototype_evaluation_model(EvaluationModelType.EVAL_CURRENT)
        self.assertEqual(eval_model.name(), "__stdcall")

    def test_CallFixupExtension(self):
        myfixup = "<callfixup name=\"mynewthing\">\n" \
                  "   <target name=\"targ1\"/>\n" \
                  "   <pcode>\n" \
                  "     <body><![CDATA[\n" \
                  "     *ESP  = 1000:4;\n" \
                  "    ESP  = ESP - 4;\n" \
                  "    *:4 ESP  = inst_next;\n" \
                  "     ]]></body>\n" \
                  "</pcode>\n" \
                  "</callfixup>\n"
        spec_extension = SpecExtension(program)
        id1 = program.start_transaction("test extension install")
        try:
            spec_extension.add_replace_compiler_spec_extension(myfixup, TaskMonitor.DUMMY)
        except (LockException, SleighException, SAXException, XmlParseException) as ex:
            self.fail(f"Unexpected exception: {ex.getMessage()}")
        program.end_transaction(id1, True)

        library = program.getCompilerSpec().getPcodeInjectLibrary()
        payloads = library.getProgramPayloads()
        assert len(payloads) == 1
        payload = payloads[0]
        assert isinstance(payload, InjectPayloadCallfixup)
        callfixup = (payload)
        targets = callfixup.getTargets()
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0], "targ1")
        self.assertEqual(payload.name(), "mynewthing")

        id = program.start_transaction("test extensions")
        first_addr = Address(program.getAddressFactory().getDefaultAddressSpace(), 0x1002607)
        func1 = program.getFunctionManager().getFunctionAt(first_addr)
        func1.set_call_fixup("mynewthing")
        second_addr = Address(program.getAddressFactory().getDefaultAddressSpace(), 0x10038d7)

        func = program.getFunctionManager().getFunctionAt(second_addr)
        func.set_signature_source(SourceType.DEFAULT)
        program.end_transaction(id, True)

        decompile("100263c")

        line = get_line_containing("injection: mynewthing")
        assert line is not None

        # injection causes remaining call to look like it takes 1000 as a parameter
        line = get_line_starting("FUN_010038d7(1000);")
        assert line is not None

        id2 = program.start_transaction("test extension removal")
        try:
            spec_extension.remove_compiler_spec_extension("callfixup_mynewthing", TaskMonitor.DUMMY)
        except (LockException, CancelledException) as ex:
            self.fail(f"Unexpected exception: {ex.getMessage()}")
        program.end_transaction(id2, True)

        payloads = library.getProgramPayloads()
        assert payloads is None

        decompile("100263c")

        line = get_line_starting("FUN_01002607();")
        assert line is not None
        line = get_line_starting("FUN_010038d7();")
        assert line is not None