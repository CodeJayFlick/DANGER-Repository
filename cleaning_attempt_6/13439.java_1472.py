import ghidra.app.service as service
from ghidra.program.model.address import GenericAddress
from ghidra.program.model.data import ByteDataType
from ghidra.program.model.listing import CodeUnit
from ghidra.util.exception import InvalidInputException

class EquatePluginScreenShots:
    def __init__(self):
        self.cb = None
        self.set_action = None
        self.equate_plugin = None
        self.listing = None
        self.remove_action = None
        self.apply_enum = None

    def tearDown(self):
        service.close_all_windows()
        super().tearDown()

    def setUp(self):
        super().setUp()
        
        flow_arrow_plugin = get_plugin(tool, 'FlowArrowPlugin')
        tool.remove_plugins([flow_arrow_plugin])

        equate_plugin = get_plugin(tool, 'EquatePlugin')
        self.cb = get_plugin(tool, 'CodeBrowserPlugin')

        env.show_tool(program)
        
        set_action = get_action(equate_plugin, "Set Equate")
        remove_action = get_action(equate_plugin, "Remove Equate")
        apply_enum = get_action(equate_plugin, "Apply Enum")

        listing = program.get_listing()

        create_equate_data()
    
    def create_equate_data(self):
        tx_id = program.start_transaction("TEST")

        # Set some equates.  These address must contain valid scalars or the equates
        # will fail to be set and our tests will not operate as expected.  So make
        # sure these locations are defined.
        
        cmd = CreateDataCmd(GenericAddress(0x0040e00d), ByteDataType())
        cmd.apply_to(program)
        cmd = CreateDataCmd(GenericAddress(0x00401013), ByteDataType())
        cmd.apply_to(program)
        cmd = CreateDataCmd(GenericAddress(0x00401031), ByteDataType())
        cmd.apply_to(program)
        cmd = CreateDataCmd(GenericAddress(0x00401053), ByteDataType())
        cmd.apply_to(program)
        cmd = CreateDataCmd(GenericAddress(0x0040c27c), ByteDataType())  # Bad equate addr
        cmd.apply_to(program)
        cmd = CreateDataCmd(GenericAddress(0x0040c238), ByteDataType())  # Enum based equate addr
        cmd.apply_to(program)

        set_equate(0x0040e00d, "EQ_1")
        set_equate(0x00401013, "EQ_2")
        set_equate(0x00401031, "EQ_3")
        set_equate(0x00401053, "EQ_4")
        set_equate(0x0040c27c, "dtID:0123456789012345678:0")
        set_equate(0x0040c238, "__FAVOR_ATOM")

        program.end_transaction(tx_id, True)

    def test_equates_table(self):
        show_provider(EquateTableProvider)
        capture_isolated_provider(EquateTableProvider, 611, 345)

    def test_confirm_equate_delete(self):
        show_provider(EquateTableProvider)
        perform_action("Delete Equate", "EquateTablePlugin", False)

        wait_for_dialog_component(OptionDialog)
        capture_dialog(OptionDialog)

    # ... and so on for the rest of the methods
