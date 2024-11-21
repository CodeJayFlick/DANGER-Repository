import unittest
from ghidra_app.plugin.core.stackeditor import StackEditorActions2Test
from ghidra.app.plugin.core.compositeeditor import CycleGroupAction
from ghidra.program.model.data import *
from ghidra.program.model.listing import *

class TestStackEditorActions2(unittest.TestCase):

    def setUp(self):
        self.super = super(StackEditorActions2Test, self)
        self.super.setUp()

    @unittest.skip("Not implemented")
    def testApplyComponentChange(self):
        # Edit the stack
        edit_stack(function.get_entry_point().to_string())

        # Set local var at -0x8
        set_selection([2])
        invoke(get_cycle_group(new ByteDataType()))
        assertEquals("", model.getStatus())
        close_editor()

    @unittest.skip("Not implemented")
    def testApplyDataTypeChanges(self):
        # Edit the stack
        edit_stack(function.get_entry_point().to_string())

        # Change 0x10 to char
        set_selection([11])
        invoke(get_cycle_group(new CharDataType()))
        assertEquals("", model.getStatus())
        close_editor()

    @unittest.skip("Not implemented")
    def testApplyLocalSizeChange(self):
        # Edit the stack
        edit_stack(function.get_entry_point().to_string())

        # Change local size from 0x20 to 0x18
        set_field(local_size_field, "0x18")
        assertEquals("", model.getStatus())
        close_editor()

    @unittest.skip("Not implemented")
    def testApplyNoVarStack(self):
        # Edit the stack
        edit_stack(function.get_entry_point().to_string())

        # Select all and clear.
        run_swing(lambda: get_table().select_all(), True)
        invoke(clear_action)
        assertEquals("", model.getStatus())
        close_editor()

    @unittest.skip("Not implemented")
    def testApplyParamSizeChange(self):
        # Edit the stack
        edit_stack(function.get_entry_point().to_string())

        # Change param size from 0x9 to 0xf
        set_field(param_size_field, "0xf")
        assertEquals("", model.getStatus())
        close_editor()

    @unittest.skip("Not implemented")
    def testApplyParamSizeChangeThatReduces(self):
        # Edit the stack
        edit_stack(function.get_entry_point().to_string())

        # Change param size from 0xd to 0xa
        set_field(param_size_field, "0xa")
        assertEquals("", model.getStatus())
        close_editor()

    @unittest.skip("Not implemented")
    def testArrayBeforeUndefineds(self):
        init(SIMPLE_STACK)

        # Duplicate Word
        set_selection([1])
        dt = get_data_type(1)
        check_selection([0])

        # Cancel the array dialog
        invoke(array_action, False)
        assertEquals("", model.getStatus())
        close_editor()

    @unittest.skip("Not implemented")
    def testCancelArray(self):
        init(SIMPLE_STACK)

        set_selection([1])
        dt = get_data_type(1)
        check_selection([0])

        # Cancel the array dialog
        invoke(array_action, False)
        assertEquals("", model.getStatus())
        close_editor()

    @unittest.skip("Not implemented")
    def testClearAction(self):
        init(SIMPLE_STACK)

        set_selection([2])
        dt = get_data_type(1)

        # Clear action
        invoke(clear_action)
        assertEquals("", model.getStatus())
        check_selection([0, 1, 2])

    @unittest.skip("Not implemented")
    def testCreateCycleDataTypeOnPointer(self):
        init(SIMPLE_STACK)

        set_selection([0])
        invoke(pointer_action)
        assertEquals("", model.getStatus())

    @unittest.skip("Not implemented")
    def testCreatePointerOnPointer(self):
        init(SIMPLE_STACK)

        ordinal = 5
        num = model.get_num_components()
        assert_cell_string("pointer32", ordinal, model.get_data_type_column())
        dt = get_data_type(ordinal)
        set_selection([ordinal])
        invoke(pointer_action)
        assertEquals("", model.getStatus())

if __name__ == '__main__':
    unittest.main()
