import unittest
from ghidra_app_plugin_core_overview import OverviewColorPlugin
from ghidra_framework_plugintool import PluginTool
from ghidra_program_database import ProgramBuilder
from ghidra_program_model_address import Address, AddressFactory
from ghidra_program_model_data import ByteDataType

class TestOverview(unittest.TestCase):
    def setUp(self):
        self.env = None
        self.tool = None
        self.addr_factory = None
        self.program = None
        self.plugin = None
        self.service = None
        self.component = None

    def test_colors(self):
        colors = getattr(component, 'colors')
        for i in range(len(colors)):
            cur_addr = get_address(i, colors)
            cur_color = colors[i]
            if cur_color == service.get_color(AddressType.INSTRUCTION):
                assert program.get_listing().get_instruction_containing(cur_addr) is not None
            elif cur_color == service.get_color(AddressType.DATA):
                self.assertTrue(program.get_listing().get_data_containing(cur_addr).is_defined())
            elif cur_color == service.get_color(AddressType.FUNCTION):
                assert program.get_listing().get_function_containing(cur_addr) is not None
            elif cur_color == service.get_color(AddressType.UNDEFINED):
                assert program.get_listing().get_instruction_containing(cur_addr) is None
                self.assertFalse(program.get_listing().get_data_containing(cur_addr).is_defined())
            elif cur_color == service.get_color(AddressType.UNINITIALIZED):
                self.assertFalse(program.get_memory().get_block(cur_addr).is_initialized())

    def get_address(self, pixel_index, colors):
        map = getattr(component, 'map')
        big_height = BigInteger(colors.__len__()).to_python()
        big_pixel_index = BigInteger(pixel_index)
        big_index = (big_height * big_pixel_index) // 1
        return map.get_address(big_index)

    def load_program(self, program_name):
        self.program = build_program(program_name)
        pm = tool.get_service(ProgramManager)
        pm.open_program(self.program.get_domain_file())
        self.addr_factory = self.program.get_address_factory()

    def build_program(self, program_name):
        builder = ProgramBuilder(program_name, 0x10000)
        for i in range(0x1000):
            builder.apply_data_type(f"0x{hex(i)}", ByteDataType())
        return builder.get_program()

if __name__ == '__main__':
    unittest.main()
