import unittest
from ghidra_framework import *
from ghidra_program_database import ProgramDB
from ghidra_address import Address
from ghidra_data_type import DataType
from ghidra_listing import Listing
from ghidra_symbol_table import SymbolTable

class VTMatchAcceptTest(unittest.TestCase):

    def setUp(self):
        self.env = TestEnv()
        source_builder = ClassicSampleX86ProgramBuilder()
        destination_builder = ClassicSampleX86ProgramBuilder()

        self.source_program = source_builder.get_program()
        self.destination_program = destination_builder.get_program()
        self.destination_program.add_listener(DomainObjectListenerRecorder())

        tool = self.env.get_tool()
        plugin = get_plugin(tool, VTPlugin)
        controller = VTControllerImpl(plugin)

        session = create_vt_session("Test Match Set Manager", self.source_program, self.destination_program, self)
        run_swing(lambda: controller.open_version_tracking_session(session))

        options = controller.get_options()
        options.set_boolean(VTOptionDefines.AUTO_CREATE IMPLIED_MATCH, False)
        options.set_boolean(VTOptionDefines.APPLY_FUNCTION_NAME_ON_ACCEPT, False)
        options.set_boolean(VTOptionDefines.APPLY_DATA_NAME_ON_ACCEPT, False)

    def tearDown(self):
        wait_for_busy_tool(tool)
        self.destination_program.flush_events()
        wait_for_posted_swing_runnables()

    @unittest.skip
    def test_accept_with_apply_data_labels(self):

        address = Address("0x0100808c", self.source_program)
        destination_address = Address("0x0100808c", self.destination_program)

        options.set_boolean(VTOptionDefines.APPLY_DATA_NAME_ON_ACCEPT, True)

        source_data_type = DWordDataType()
        destination_data_type1 = StringDataType()
        destination_data_type2 = WordDataType()

        set_data(source_data_type, 4, address, self.source_program)
        set_data(destination_data_type1, 2, destination_address, self.destination_program)
        set_data(destination_data_type2, 2, destination_address.add(2), self.destination_program)

        add_label("Bob", address, self.source_program)

        match = create_match_set_with_one_data_match(session, source_address, destination_address)
        task = AcceptMatchTask(controller, [match])
        run_task(task)

        status = match.get_association().get_status()
        assertEqual(VTAssociationStatus.ACCEPTED, status)
        assertEquals("Bob", self.destination_program.symbol_table.get_primary_symbol(destination_address).name)

    def add_label(self, name, address, program):
        symbol_table = program.symbol_table
        transaction = -1

        try:
            transaction = program.start_transaction("Test - Add Label")
            return symbol_table.create_label(address, name, SourceType.USER_DEFINED)
        finally:
            program.end_transaction(transaction, True)

    def run_task(self, task):
        task.run(TaskMonitor.DUMMY)
        self.destination_program.flush_events()
        wait_for_posted_swing_runnables()

    def set_data(self, data_type, dt_length, address, program):
        listing = program.listing
        transaction = program.start_transaction("Test - Set Data")

        try:
            return listing.create_data(address, data_type, dt_length)
        finally:
            program.end_transaction(transaction)

class DomainObjectListenerRecorder(DomainObjectListener):

    def __init__(self):
        self.events = []

    def domain_object_changed(self, ev):
        self.events.append(ev)

if __name__ == "__main__":
    unittest.main()
