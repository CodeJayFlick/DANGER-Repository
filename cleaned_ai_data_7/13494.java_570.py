import unittest
from ghidra.program.model import ProgramDB, AddressSet
from ghidra.app.services import ProgramManager
from ghidra.framework.plugintool.util import PluginException
from ghidra. program.database import ProgramDB

class AbstractDataReferenceGraphTest(unittest.TestCase):

    def setUp(self):
        self.setErrorGUIEnabled(False)
        self.env = TestEnv()
        self.tool = env.getTool()

        self.initializeTool()

    def tearDown(self):
        self.env.dispose()

    def initializeTool(self):
        self.installPlugins()

        self.openProgram()
        program_manager = tool.getService(ProgramManager)
        program_manager.openProgram(program.getDomainFile())

        show_tool(tool)

    def install_plugins(self):
        try:
            tool.add_plugin(CodeBrowserPlugin.getName())
            code_browser = env.get_plugin(CodeBrowserPlugin)
        except PluginException as e:
            print(f"Error installing plugins: {e}")

    def open_program(self):
        self.builder = ToyProgramBuilder("sample", True)

        self.builder.create_memory("data", "0x01000000", 64)
        self.builder.create_memory("caller", "0x01002200", 8)

        build_function()
        build_data()

        program = builder.get_program()

    def build_data(self):
        try:
            self.builder.create_string("0x01000000", "thing here", StandardCharsets.US_ASCII, True,
                                       StringDataType.data_type)
            self.builder.create_memory_reference("0x0100000c", "0x0100000f", RefType.DATA, SourceType.ANALYSIS)

            self.builder.create_string("0x0100000f", "another thing", StandardCharsets.US_ASCII, True,
                                       StringDataType.data_type)

            self.builder.add_data_type(IntegerDataType.data_type)
            self.builder.create_memory_reference("0x01000021", "0x0100000c", RefType.DATA, SourceType.ANALYSIS)

            pointer_structure = StructureDataType("pointer_thing", 0)
            pointer_structure.set_packing_enabled(True)
            pointer_structure.add(IntegerDataType.data_type, "num", None)
            pointer_structure.add(PointerDataType.data_type, "ptr", None)
            self.builder.add_data_type(pointer_structure)
            self.builder.apply_data_type("0x0100001d", pointer_structure)

        except Exception as e:
            print(f"Error building data: {e}")

    def build_function(self):
        try:
            # just a function that calls another
            self.builder.create_memory_reference("0x1002200", "0x01000000", RefType.DATA, SourceType.ANALYSIS)
            self.builder.add_bytes_call("0x01002201", "0x01002239")  # jump to C
            self.builder.add_bytes_return("0x01002203")

            self.builder.disassemble("0x01002200", 4, True)

            self.builder.create_function("0x01002200")
            self.builder.create_label("0x01002200", "entry")  # function label

        except Exception as e:
            print(f"Error building function: {e}")

    def addr(self, address):
        return builder.get_address(address)

    def addr_set(self, start, end):
        return AddressSet(addr(start), addr(end))

if __name__ == "__main__":
    unittest.main()
