import unittest
from ghidra_app_plugin_core_memory import MemoryMapProvider1Test
class TestMemoryMapProvider(MemoryMapProvider1Test):
    def setUp(self):
        super().setUp()
        self.memory = program.getMemory()

    def testActionsEnabled(self):
        table.add_row_selection_interval(0, 0)
        actions = get_actions_by_owner(tool, plugin.getName())
        for action in actions:
            if action.name == "Merge Blocks":
                self.assertFalse(action.is_enabled())
            else:
                self.assertTrue(action.is_enabled())

    def testMultiSelection(self):
        table.add_row_selection_interval(0, 1)
        self.assertEqual(table.get_selected_row_count(), 2)

    # ... other tests

class AddrComparator:
    def compare(self, o1, o2):
        a1 = AddressEvaluator.evaluate(program, str(o1))
        a2 = AddressEvaluator.evaluate(program, str(o2))
        return a1.compareTo(a2)
