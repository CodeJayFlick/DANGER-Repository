Here is a translation of the provided Java code into equivalent Python:

```Python
import unittest
from ghidra_app_service import GhidraAppService
from ghidra_program_model_address import Address
from ghidra_program_model_listing import Listing
from ghidra_program_model_memory import Memory
from ghidra_function_comparison_provider_manager import FunctionComparisonProviderManager

class TestFunctionComparisonScreenShots(unittest.TestCase):

    def setUp(self):
        self.app_service = GhidraAppService()
        self.source_program = self.app_service.load_program("VersionTracking/WallaceSrc")
        self.destination_program = self.app_service.load_program("VersionTracking/WallaceVersion2")

    def tearDown(self):
        pass

    def test_function_comparison_window(self):

        position_listing_top(0x004118f0)
        tx_id1 = self.source_program.start_transaction("Modify Program1")
        tx_id2 = self.destination_program.start_transaction("Modify Program2")

        try:
            source_program_domain_file_name = "FirstProgram"
            destination_program_domain_file_name = "SecondProgram"

            self.source_program.get_domain_file().set_name(source_program_domain_file_name)
            self.destination_program.get_domain_file().set_name(destination_program_domain_file_name)

            listing1 = self.source_program.get_listing()
            listing2 = self.destination_program.get_listing()

            memory = self.source_program.get_memory()

            f1 = get_function(self.source_program, 0x004118f0)
            f1.set_name("FunctionA", "USER_DEFINED")

            source_listing = self.source_program.get_listing()
            source_listing.set_comment(0x004119b4, CodeUnit.PLATE_COMMENT, None)

            memory.set_byte(0x004119b2, 55)
            memory.set_byte(0x004119b4, 52)

            disassemble(self.source_program, 0x004119b1, 4, False)

            f2 = get_function(self.destination_program, 0x004118c0)
            f2.set_name("FunctionB", "USER_DEFINED")

            dest_listing = self.destination_program.get_listing()
            dest_listing.set_comment(0x004118c0, CodeUnit.PLATE_COMMENT, None)

            provider_mgr = FunctionComparisonProviderManager(self.source_program, self.destination_program)
            function_comparison_provider = provider_mgr.compare_functions(f1, f2)

            run_swing(lambda: 
                function_comparison_panel = function_comparison_provider.get_component()
                dual_listing = (ListingCodeComparisonPanel) function_comparison_panel.get_displayed_panel()
                left_panel = dual_listing.get_left_panel()
                left_panel.go_to(0x004119aa)
            )

            capture_isolated_provider(FunctionComparisonProvider, 1200, 550)

        except DuplicateNameException | InvalidInputException | MemoryAccessException | InvalidNameException as e:
            print(e.stacktrace())

        finally:
            self.destination_program.end_transaction(tx_id2, False)
            self.source_program.end_transaction(tx_id1, False)


    def test_add_to_comparison_icon(self):
        f1 = get_function(self.source_program, 0x004118f0)
        f2 = get_function(self.destination_program, 0x004118c0)

        provider_mgr = FunctionComparisonProviderManager(self.source_program, self.destination_program)
        function_comparison_provider = provider_mgr.compare_functions(f1, f2)

        capture_action_icon("Add Functions To Comparison")


    def test_remove_from_comparison_icon(self):
        f1 = get_function(self.source_program, 0x004118f0)
        f2 = get_function(self.destination_program, 0x004118c0)

        provider_mgr = FunctionComparisonProviderManager(self.source_program, self.destination_program)
        function_comparison_provider = provider_mgr.compare_functions(f1, f2)

        capture_action_icon("Remove Functions")


    def test_nav_next_icon(self):
        f1 = get_function(self.source_program, 0x004118f0)
        f2 = get_function(self.destination_program, 0x004118c0)

        provider_mgr = FunctionComparisonProviderManager(self.source_program, self.destination_program)
        function_comparison_provider = provider_mgr.compare_functions(f1, f2)

        capture_action_icon("Compare Next Function")


    def test_nav_previous_icon(self):
        f1 = get_function(self.source_program, 0x004118f0)
        f2 = get_function(self.destination_program, 0x004118c0)

        provider_mgr = FunctionComparisonProviderManager(self.source_program, self.destination_program)
        function_comparison_provider = provider_mgr.compare_functions(f1, f2)

        panel = (MultiFunctionComparisonPanel) function_comparison_provider.get_component()
        panel.focused_component.set_selected_index(1)

        capture_action_icon("Compare Previous Function")


    def test_add_functions_panel(self):
        f1 = get_function(self.source_program, 0x004118f0)
        f2 = get_function(self.destination_program, 0x004118c0)

        provider_mgr = FunctionComparisonProviderManager(self.source_program, self.destination_program)
        function_comparison_provider = provider_mgr.compare_functions(f1, f2)

        open_table_action = get_action("Add Functions To Comparison")
        perform_action(open_table_action, False)

        dialog = waitForDialogComponent(TableChooserDialog.class)
        set_column_sizes(dialog)

        capture_dialog(dialog)


    def test_disassemble(self):
        pgm1 = self.source_program
        address_as_long = 0x004119b1
        length = 4
        follow_flows = True

        disassemble(pgm1, address_as_long, length, follow_flows)


def get_function(program, entry_point):
    function_manager = program.get_function_manager()
    return function_manager.get_function_at(entry_point)


def position_listing_top(address):
    pass


def capture_isolated_provider(provider_class, width, height):
    pass


def run_swing(action):
    pass


def waitForSwing():
    pass


def set_column_sizes(dialog):
    filter = (GFilterTable) getInstanceField("gFilterTable", dialog)
    table = filter.get_table()
    for i in range(table.column_model.get_column_count()):
        column = table.column_model.get_column(i)
        header_value = column.get_header_value()
        if "Name".equals(header_value):
            column.set_preferred_width(100)
        elif "Location".equals(header_value):
            column.set_preferred_width(70)
        elif "Function Signature".equals(header_value):
            column.set_preferred_width(200)
        elif "Function Size".equals(header_value):
            column.set_preferred_width(25)


def disassemble(pgm1, address_as_long, length, follow_flows):
    pass


if __name__ == "__main__":
    unittest.main()
```

This Python code is a direct translation of the provided Java code. However, please note that this code does not include any actual functionality or logic as it was written to mimic the structure and syntax of the original Java code rather than providing working implementations.

The following functions are missing in the given Python code:

- `capture_action_icon()`
- `get_action()`
- `perform_action(action, follow_flows)`
- `waitForDialogComponent(dialog_class)`
- `getInstanceField(field_name, object)`
- `addr(address_as_long)`

These functions would need to be implemented based on your specific requirements and the actual functionality you want them to provide.