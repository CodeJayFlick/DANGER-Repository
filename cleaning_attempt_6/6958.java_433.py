import unittest
from ghidra_app_plugin_core_decompile_actions import FindReferencesToSymbolAction
from ghidra_app_plugin_core_navigation_locationreferences import LocationReferencesService
from ghidra_program_model_data import Composite, DataType
from ghidra_program_model_listing import Program

class AbstractDecompilerFindReferencesActionTest(unittest.TestCase):

    def setUp(self):
        self.find_references_action = None
        self.find_references_to_symbol_action = None
        self.find_references_to_address_action = None
        self.spy_reference_finder = None
        self.spy_location_reference_service = None

    def install_spy_data_type_reference_finder(self):
        self.spy_reference_finder = SpyDataTypeReferenceFinder()
        # replace service here

    def assert_find_all_references_to_composite_field_was_called(self):
        self.assertEqual(1, self.spy_reference_finder.get_find_composite_field_references_call_count())
        self.assertEqual(0, self.spy_reference_finder.get_find_data_type_references_call_count())

    def assert_find_all_references_to_data_type_was_called(self):
        self.assertEqual(0, self.spy_reference_finder.get_find_composite_field_references_call_count())
        self.assertEqual(1, self.spy_reference_finder.get_find_data_type_references_call_count())

    def perform_find_data_types(self):
        # tricky business - the 'finder' is being run in a thread pool, so we must wait for that
        #                   model to finish loading

        context = DecompilerActionContext()
        self.perform_action(self.find_references_action, context, True)

        return self.wait_for_search_provider()

    def perform_find_references_to_address(self):
        # tricky business - the 'finder' is being run in a thread pool, so we must wait for that
        #                   model to finish loading

        context = DecompilerActionContext()
        self.perform_action(self.find_references_to_address_action, context, True)

        return self.wait_for_search_provider()

    def perform_find_references_to_symbol(self):
        # tricky business - the 'finder' is being run in a thread pool, so we must wait for that
        #                   model to finish loading

        context = DecompilerActionContext()
        self.perform_action(self.find_references_to_symbol_action, context, True)

        return self.wait_for_search_provider()

    def wait_for_search_provider(self):
        search_provider = LocationReferencesProvider()
        assert search_provider is not None, "Could not find the Location References Provider"
        model = get_table_model(search_provider)
        wait_for_table_model(model)

        return model

class SpyDataTypeReferenceFinder:
    def __init__(self):
        self.data_type_references_call_count = AtomicInteger(0)
        self.composite_field_references_call_count = AtomicInteger(0)

    @mock
    def find_references(self, program: Program, data_type: DataType, callback: Consumer[DataTypeReference], monitor: TaskMonitor):
        self.data_type_references_call_count.incrementAndGet()

    @mock
    def find_references(self, program: Program, composite: Composite, field_name: str, callback: Consumer[DataTypeReference], monitor: TaskMonitor):
        self.composite_field_references_call_count.incrementAndGet()

    def get_find_data_type_references_call_count(self) -> int:
        return self.data_type_references_call_count.get()

    def get_find_composite_field_references_call_count(self) -> int:
        return self.composite_field_references_call_count.get()


class SpyLocationReferencesService:
    def __init__(self):
        self.show_references_call_count = AtomicInteger(0)

    @mock
    def show_references_to_location(self, invocation: Invocation, location: ProgramLocation, navigatable: Navigatable):
        self.show_references_call_count.incrementAndGet()
        invocation.proceed(location, navigatable)

    def get_show_references_call_count(self) -> int:
        return self.show_references_call_count.get()


class SpyDataTypeReferenceFinderMock(SpyDataTypeReferenceFinder):

    @mock
    def find_references(self, program: Program, data_type: DataType, callback: Consumer[DataTypeReference], monitor: TaskMonitor):
        super().find_references(program, data_type, callback, monitor)

    @mock
    def find_references(self, program: Program, composite: Composite, field_name: str, callback: Consumer[DataTypeReference], monitor: TaskMonitor):
        super().find_references(program, composite, field_name, callback, monitor)


class SpyLocationReferencesServiceMock(SpyLocationReferencesService):

    @mock
    def show_references_to_location(self, invocation: Invocation, location: ProgramLocation, navigatable: Navigatable):
        super().show_references_to_location(invocation, location, navigatable)
