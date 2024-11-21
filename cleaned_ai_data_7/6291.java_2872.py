import unittest
from ghidra.app.plugin.core.compositeeditor import *
from docking.widgets.dialogs import *

class StructureEditorLockedActions3Test(unittest.TestCase):

    def testExistingDtEditInternalStructureOnSelectionVariousNames(self):
        init(simple_structure, pgm_bb_cat)
        self.assertEqual(8, getModel().getNumComponents())
        
        set_selection([1, 2, 3])
        original_dt1 = get_data_type(1)
        original_dt2 = get_data_type(2)
        original_dt3 = get_data_type(3)
        original_dt4 = get_data_type(4)

        # Make selected components into internal structure.
        invoke(create_internal_structure_action, False)

        # Specify name for structure.
        input_dialog = waitForDialogComponent(InputDialog.class)
        assertNotNull(input_dialog)

        text_fields = getInstanceField("textFields", input_dialog)[0]
        textField = text_fields[0]
        triggerText(textField, "simpleStructure")
        pressButtonByText(input_dialog, "OK")
        waitUntilSwing()

        self.assertEqual("The name cannot match the external structure name.",
                         getStatusText(input_dialog))
        assertTrue(isShowing(input_dialog))

        setText(textField, "simpleUnion")
        pressButtonByText(input_dialog, "OK")
        self.assertEqual("A data type named \"simpleUnion\" already exists.",
                         getStatusText(input_dialog))
        assertTrue(isShowing(input_dialog))

        setText(textField, "Foo")
        pressButtonByText(input_dialog, "OK")
        self.assertEqual("", getStatusText(input_dialog))
        assertFalse(isShowing(input_dialog))
        waitUntilTasks()

        self.assertEqual(6, getModel().getNumComponents())
        internal_struct = get_data_type(1)
        self.assertEqual("Foo", internal_struct.getName())
        self.assertEqual(3, internal_struct.getNumComponents())
        dt0 = internal_struct.getComponent(0).getDataType()
        dt1 = internal_struct.getComponent(1).getDataType()
        dt2 = internal_struct.getComponent(2).getDataType()
        assertTrue(dt0.isEquivalent(original_dt1))
        assertTrue(dt1.isEquivalent(original_dt2))
        assertTrue(dt2.isEquivalent(original_dt3))
        self.assertEqual(7, get_data_type(1).getLength())
        self.assertEqual(29, getModel().getLength())

    def testFavoritesFixedOnComponent(self):
        init(simple_structure, pgm_bb_cat)
        
        dt = getModel().getOriginalDataTypeManager().getDataType("/byte")
        assertNotNull(dt)

        fav = FavoritesAction(provider, dt)

        set_selection([3])
        assertFalse(get_data_type(3).isEquivalent(dt))
        invoke(fav)
        self.assertEqual(11, getModel().getNumComponents())
        assertTrue(get_data_type(3).isEquivalent(dt))

    def testFavoritesFixedOnMultiple(self):
        init(simple_structure, pgm_bb_cat)

        dt = getModel().getOriginalDataTypeManager().getDataType("/byte")
        assertNotNull(dt)

        fav = FavoritesAction(provider, dt)
        
        num_components = getModel().getNumComponents()
        set_selection([2, 3])
        original_dt4 = get_data_type(4)
        invoke(fav)
        assertTrue(get_data_type(3).isEquivalent(dt))
        assertTrue(get_data_type(8).isEquivalent(original_dt4))

    def testFavoritesFixedOnUndefined(self):
        init(simple_structure, pgm_bb_cat)

        dt = getModel().getOriginalDataTypeManager().getDataType("/byte")
        assertNotNull(dt)
        
        num_components = getModel().getNumComponents()
        set_selection([0])
        assertFalse(get_data_type(0).isEquivalent(dt))
        invoke(fav)
        self.assertEqual(num_components, getModel().getNumComponents())
        assertTrue(get_data_type(0).isEquivalent(dt))

    def testFavoritesOnPointer(self):
        init(complex_structure, pgm_bb_cat)

        dt = getModel().getOriginalDataTypeManager().getDataType("/word")
        assertNotNull(dt)

        fav = FavoritesAction(provider, dt)
        
        self.assertEqual(325, getModel().getLength())
        self.assertEqual(23, getModel().getNumComponents())

    def testFavoritesVariableOnBlank(self):
        init(simple_structure, pgm_bb_cat)

        dialog
        dt = getModel().getOriginalDataTypeManager().getDataType("/string")
        assertNotNull(dt)
        
        fav = FavoritesAction(provider, dt)

        num_components = getModel().getNumComponents()
        set_selection([4])
        invoke(fav, False)
        dialog = waitForDialogComponent(NumberInputDialog.class)
        okInput(dialog, 8)
        dialog.dispose()

    def testNoFitPointerOnFixedDt(self):
        init(simple_structure, pgm_bb_cat)

        model.clear_components([2])

        dt1 = get_data_type(1)
        set_selection([1])
        invoke(pointer_action)
        
        self.assertEqual(9, getModel().getNumComponents())
        assertEquals("byte", get_data_type(1).getName())
        assertTrue(get_data_type(1) == dt1)

    #def testCancelPointerOnFixedDt(self):
    #    provider = StructureEditorProvider(plugin, program, complex_structure, pgm_test_cat, dtm_service)
    #    model = (StructureEditorModel)provider.getModel()
    #    get_actions()

    def testCreatePointerOnStructPointer(self):
        init(complex_structure, pgm_bb_cat)

        set_selection([5])
        dt5 = get_data_type(5)
        
        invoke(pointer_action)
        
        self.assertEqual(num_components, getModel().getNumComponents())
        assertEquals("simpleStructure *", get_data_type(5).getName())

    def testCreatePointerOnArray(self):
        init(complex_structure, pgm_bb_cat)

        set_selection([10])
        dt10 = get_data_type(10)
        
        invoke(pointer_action, False)
        dialog = waitForDialogComponent(NumberInputDialog.class)
        okInput(dialog, 2)
        dialog.dispose()

    def testCreatePointerOnTypedef(self):
        init(complex_structure, pgm_bb_cat)

        set_selection([15])
        dt15 = get_data_type(15)
        
        invoke(pointer_action, False)
        dialog = waitForDialogComponent(NumberInputDialog.class)
        okInput(dialog, 4)
        dialog.dispose()

    def testApplyComponentChange(self):
        init(complex_structure, pgm_bb_cat)

        component = find_component_by_name(provider.editor_panel, "Total Length")
        assertNotNull(component)
        assertEquals(True, component.isEnabled())

if __name__ == "__main__":
    unittest.main()
