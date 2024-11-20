import unittest
from ghidra_app_plugin_core_debug_gui_memory import DebuggerRegionsProvider
from ghidra_app_plugin_core_debug_gui_listing import DebuggerListingPlugin
from ghidra_program_model_address import AddressSet
from ghidra_trace_model_memory import TraceMemoryRegion

class TestDebuggerRegionsProvider(unittest.TestCase):

    def setUp(self):
        self.provider = DebuggerRegionsProvider()

    @unittest.skip("Not implemented")
    def test_no_trace_empty(self):
        self.assertEqual(0, len(self.provider.region_table_model.get_data()))

    @unittest.skip("Not implemented")
    def test_activate_empty_trace_empty(self):
        # create and open trace
        pass

    @unittest.skip("Not implemented")
    def test_add_then_activate_trace_populates(self):
        region = TraceMemoryRegion()
        try:
            self.provider.add_region(region)
        except Exception as e:
            print(f"Error: {e}")

        self.assertEqual(1, len(self.provider.region_table_model.get_data()))
        row = next(iter(self.provider.region_table_model.get_data()))
        self.assertEqual(region, row['region'])
        self.assertEqual("bin:.text", row['name'])

    @unittest.skip("Not implemented")
    def test_activate_trace_then_add_populates(self):
        # create and open trace
        pass

        try:
            region = TraceMemoryRegion()
            self.provider.add_region(region)
        except Exception as e:
            print(f"Error: {e}")

        row = next(iter(self.provider.region_table_model.get_data()))
        self.assertEqual(region, row['region'])

    @unittest.skip("Not implemented")
    def test_delete_removes(self):
        region = TraceMemoryRegion()
        try:
            self.provider.add_region(region)
        except Exception as e:
            print(f"Error: {e}")

        # delete the region
        pass

        self.assertEqual(0, len(self.provider.region_table_model.get_data()))

    @unittest.skip("Not implemented")
    def test_undo_redo(self):
        try:
            region = TraceMemoryRegion()
            self.provider.add_region(region)
        except Exception as e:
            print(f"Error: {e}")

        # undo and redo
        pass

    @unittest.skip("Not implemented")
    def test_abort(self):
        # create and open trace
        pass

        try:
            region = TraceMemoryRegion()
            self.provider.add_region(region)
        except Exception as e:
            print(f"Error: {e}")

        # abort the transaction
        pass

    @unittest.skip("Not implemented")
    def test_double_click_navigates(self):
        listing_plugin = DebuggerListingPlugin()

        try:
            region = TraceMemoryRegion()
            self.provider.add_region(region)
        except Exception as e:
            print(f"Error: {e}")

        # double click on the row
        pass

        self.assertEqual(tb.addr(0x00400000), listing_plugin.get_location().get_address())

    @unittest.skip("Not implemented")
    def test_action_select_addresses(self):
        listing_plugin = DebuggerListingPlugin()

        try:
            region = TraceMemoryRegion()
            self.provider.add_region(region)
        except Exception as e:
            print(f"Error: {e}")

        # select the addresses
        pass

        self.assertEqual(tb.set(tb.range(0x00400000, 0x0040ffff)), new AddressSet(listing_plugin.get_selection()))

    @unittest.skip("Not implemented")
    def test_action_select_rows(self):
        listing_plugin = DebuggerListingPlugin()

        try:
            region = TraceMemoryRegion()
            self.provider.add_region(region)
        except Exception as e:
            print(f"Error: {e}")

        # select the rows
        pass

        self.assertEqual(set([row]), set.copy(provider.get_selected_rows()))

if __name__ == '__main__':
    unittest.main()
