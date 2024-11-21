Here is your Java code translated into Python:

```Python
import unittest
from ghidra.app.plugin.core.navigation import NextPrevAddressPluginTest
from ghidra.framework.plugintool import PluginTool
from ghidra.program.model.address import Address
from ghidra.program.model.listing import Program
from ghidra.program.model.mem import Memory
from ghidra.program.model.symbol import Symbol, SymbolIterator

class TestNextPrevAddressPlugin(unittest.TestCase):

    def setUp(self):
        self.env = None  # To be implemented
        self.program = None  # To be implemented
        self.tool = None  # To be implemented
        self.previous_action = None  # To be implemented
        self.next_action = None  # To be implemented
        self.prev_function_action = None  # To be implemented
        self.next_function_action = None  # To be implemented
        self.cb_plugin = None  # To be implemented

    def tearDown(self):
        if self.env is not None:
            self.env.dispose()

    def test_navigation_from_middle_of_pulldown_action(self):

        navigated_symbols = do_bulk_go_to()
        reversed_navigated_symbols = list(reversed(navigated_symbols))  # the list was in reverse stack order, so fix it

        bulk_navigation_symbol = navigated_symbols.pop(0)  # the front of the list will not be on the navigation stack, since it is the current address
        self.assertEqual(len(self.previous_action.get_action_list()), len(navigated_symbols) + 1)

        for i in range(len(self.previous_action.get_action_list()) - 1):
            dockable_action = self.previous_action.get_action_list()[i]
            location = LocationMemento(dockable_action)
            symbol = navigated_symbols[i]

            program_location = location.get_program_location()
            self.assertEqual(program_location.get_address(), symbol.get_address())

        # pick one of the items in the list and go back to that item...
        action = self.previous_action.get_action_list()[4]
        symbol = navigated_symbols[4]
        perform_action(action, True)
        self.assertEqual(symbol.get_address(), current_address())

    def test_backward_and_forward(self):

        start_address = current_address()
        second_address = addr("010018a0")
        go_to(second_address)

        previous()
        assert_current_address(start_address)

        next()
        assert_current_address(second_address)

        # try the drop-down popup
        previous_by_dropdown()
        assert_current_address(start_address)

        next_by_drowdown()
        assert_current_address(second_address)

    def test_function_navigation_only_functions_in_history(self):

        f1 = addr("01002cf5")  # ghidra
        f2 = addr("01006420")  # entry
        f3 = addr("0100415a")  # sscanf

        self.assert_disabled(previous_function_action)
        self.assert_disabled(next_function_action)

        go_to(f1)
        self.assert_disabled(previous_function_action)
        self.assert_disabled(next_function_action)

        go_to(f2)
        self.assert_enabled(previous_function_action)
        self.assert_disabled(next_function_action)

        go_to(f3)
        self.assert_enabled(previous_function_action)
        self.assert_disabled(next_function_action)

        previous_function()
        assert_current_address(f2)
        self.assert_enabled(previous_function_action)
        self.assert_enabled(next_function_action)

        previous_function()
        assert_current_address(f1)
        self.assert_disabled(previous_function_action)
        self.assert_enabled(next_function_action)

    def test_function_navigation_mixed_history(self):

        f1 = addr("01002cf5")  # ghidra
        a1 = f1.add(1)
        a2 = f1.add(3)
        a3 = f1.add(8)
        f2 = addr("01006420")  # entry

        self.assert_disabled(previous_function_action)
        self.assert_disabled(next_function_action)

        go_to(f1)
        self.assert_disabled(previous_function_action)
        self.assert_disabled(next_function_action)

        go_to(a1)
        go_to(a2)
        go_to(a3)
        self.assert_disabled(previous_function_action)
        self.assert_disabled(next_function_action)

        go_to(f2)
        self.assert_enabled(previous_function_action)
        self.assert_disabled(next_function_action)

    def perform_action(self, action):
        # To be implemented

    def previous_by_dropdown(self):
        # To be implemented

    def next_by_drowdown(self):
        # To be implemented

    def do_bulk_go_to(self):
        list = []
        memory = program.get_memory()
        count = 0
        iter = program.get_symbol_table().get_all_symbols(True)
        while iter.has_next() and count < 11:
            symbol = iter.next()
            addr = symbol.get_address()
            if (addr.is_memory_address() and not memory.contains(addr) or addr.is_external_address()):
                continue
            list.append(symbol)
            go_to(symbol)
            count += 1
        return list

    def current_address(self):
        # To be implemented

if __name__ == '__main__':
    unittest.main()
```

Please note that this is a direct translation of your Java code into Python. It might not work as expected without proper implementation and testing, especially for the parts marked `# To be implemented`.