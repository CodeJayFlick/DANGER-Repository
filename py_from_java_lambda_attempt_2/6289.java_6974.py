Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra.app.plugin.core.compositeeditor import *
from ghidra.program.model.data import *

class StructureEditorLockedActions1Test(unittest.TestCase):

    def testArrayOnSelection(self):
        init(simpleStructure, pgmBbCat)
        set_selection([1, 2, 3])
        dt1 = get_data_type(1)
        dt4 = get_data_type(4)

        invoke(array_action)
        self.assertEqual(get_model().get_num_components(), 6)
        self.assertTrue(isinstance(get_data_type(1), Array) and isinstance(get_data_type(1).get_data_type(), dt1))
        self.assertEqual(get_data_type(1).get_length(), 7)
        self.assertEqual(get_model().get_component(1).get_length(), 7)
        self.assertEqual(get_data_type(2), dt4)

    def testArrayOnSelectionExtraUndefineds(self):
        init(simpleStructure, pgmBbCat)
        run_swing(lambda: model.clear_components([4, 5]))
        set_selection([3, 4, 5, 6, 7, 8, 9, 10]) # starts with DWord
        dt3 = get_data_type(3)
        dt11 = get_data_type(11)

        invoke(array_action)
        self.assertEqual(get_model().get_num_components(), len([1, 2, 3, 4, 5]) - 4)
        check_selection([3, 4, 5])
        self.assertTrue(isinstance(get_data_type(3), Array) and isinstance(get_data_type(3).get_data_type(), dt3))
        self.assertEqual(get_data_type(3).get_length(), 8)
        self.assertEqual(get_model().get_component(3).get_length(), 8)
        self.assertEqual(get_data_type(4), get_data_type(5)) = DataType.DEFAULT
        self.assertEqual(get_data_type(6), get_data_type(7)) = DataType.DEFAULT
        self.assertEqual(get_data_type(7), dt11)

    def testClearAction(self):
        init(complexStructure, pgmTestCat)
        run_swing(lambda: model.set_component_name(2, "comp2") and model.set_component_comment(2, "comment 2"))
        num = get_model().get_num_components()

        set_selection([2])
        dt3 = get_data_type(3)

        invoke(clear_action)
        self.assertEqual(get_model().get_num_components(), num + 1)
        check_selection([2, 3])
        self.assertEqual(get_data_type(2), DataType.DEFAULT)
        self.assertEqual(get_data_type(3), DataType.DEFAULT)
        self.assertEqual(get_data_type(4), dt3)

    def testCreateCycleOnPointer(self):
        init(simpleStructure, pgmBbCat)
        run_swing(lambda: model.clear_components([2, 3]))
        set_selection([1])
        invoke(pointer_action)
        cycle_byte = get_cycle_group(ByteDataType())
        invoke(cycle_byte)
        self.assertEqual(get_model().get_num_components(), 9)
        self.assertEqual(get_data_type(1).get_display_name(), "byte *")
        self.assertEqual(get_data_type(1).get_name(), "byte *32")
        self.assertTrue(isinstance(get_data_type(1), Pointer) and isinstance(get_data_type(1).get_data_type(), get_model().view_composite))
        self.assertEqual(get_data_type(1).get_length(), 4)
        self.assertEqual(get_model().get_component(1).get_length(), 4)

    def testCreatePointerOnUndefined(self):
        init(simpleStructure, pgmBbCat)
        model.clear_components([3])
        set_selection([3])
        invoke(pointer_action)
        self.assertEqual(get_data_type(3).get_display_name(), "pointer")
        self.assertEqual(get_data_type(3).get_name(), "pointer")
        self.assertIsNone((get_data_type(3)).get_data_type())

    def testCreatePointerToSelfAndApply(self):
        init(complexStructure, pgmTestCat)
        num = get_model().get_num_components()

        add_at_point(complexStructure, 3, 0)

        self.assertEqual(get_model().get_num_components(), num)
        self.assertEqual(get_data_type(3).get_display_name(), "complexStructure *32")
        self.assertEqual(get_data_type(3).get_name(), "complexStructure *32")
        self.assertTrue(isinstance(get_data_type(3), Pointer) and isinstance(get_data_type(3).get_data_type(), get_model().view_composite))
        self.assertEqual(get_data_type(3).get_length(), 4)
        self.assertEqual(get_model().get_component(3).get_length(), 4)

        invoke(apply_action)
        self.assertTrue(complexStructure.is_equivalent(get_model().view_composite))

    def testCycleGroupByteLotsOfRoom(self):
        init(complexStructure, pgmTestCat)
        model.clear_components([2, 3, 4]) # clear 14 bytes

        dt16 = get_data_type(16)
        num = get_model().get_num_components()
        len_ = get_model().get_length()

        set_selection([1])
        action = get_cycle_group(ByteDataType())

        invoke(action)
        self.assertEqual(get_model().get_num_components(), num - 1)
        self.assertEqual(get_model().get_length(), len_)
        self.assertTrue(isinstance(get_data_type(1), Word) and isinstance(get_data_type(2), DataType.DEFAULT))
        check_selection([1])
        self.assertEqual(get_length(1), 2)
        self.assertEqual(get_length(15), dt16.get_length())
        self.assertEqual(get_data_type(15), dt16)

    def testCycleGroupByteNoRoom(self):
        init(complexStructure, pgmTestCat)

        dt1 = get_data_type(1)
        num = get_model().get_num_components()
        len_ = get_model().get_length()

        set_selection([0])
        action = get_cycle_group(ByteDataType())

        invoke(action)
        self.assertEqual(get_model().get_num_components(), num)
        self.assertEqual(get_model().get_length(), len_)
        self.assertTrue(isinstance(get_data_type(0), Byte))
        check_selection([0])
        self.assertEqual(get_length(1), 1)
        self.assertEqual(get_data_type(1), dt1)

if __name__ == "__main__":
    unittest.main()
```

Please note that this is a direct translation of the Java code into Python, and it may not be perfect. The original Java code might have some specific requirements or assumptions that are not easily translatable to Python.