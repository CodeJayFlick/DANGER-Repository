import unittest
from ghidra.app.plugin.core.compositeeditor import *
from org.junit.assert import *

class StructureEditorUnlockedActions4Test(unittest.TestCase):

    def testChangeSizeToZero(self):
        init(complexStructure, pgmTestCat)
        original_length = complexStructure.getLength()
        new_length = 0

        self.assertEqual(original_length, model.getLength())

        waitForSwing()
        text_field = find_component_by_name(provider.editorPanel, "Total Length")
        assert text_field is not None

        set_text(text_field, str(new_length))
        trigger_enter(text_field)

        truncate_dialog = wait_for_window("Truncate Structure In Editor?")
        assert truncate_dialog is not None
        press_buttonByText(truncate_dialog, "Yes")
        waitForSwing()

        self.assertEqual(new_length, model.getLength())
        invoke(apply_action)
        self.assertTrue(complexStructure.is_equivalent(model.viewComposite))
        self.assertEqual(1, complexStructure.getLength())
        self.assertTrue(not complexStructure.is_yet_defined())
        self.assertTrue(complexStructure.is_zero_length())

    def testArrayOnVarDt(self):
        init(complexStructure, pgmTestCat)

        number_input_dialog = run_swing(lambda: model.clear_component(6))
        num_components = model.get_num_components()

        set_selection([5])
        dt_5 = get_data_type(5)
        self.assertTrue(dt_5 is not None and isinstance(dt_5, Pointer))

        # Make array of 3 pointers
        invoke(array_action, False)
        number_input_dialog = wait_for_dialog_component(NumberInputDialog)
        assert number_input_dialog is not None
        ok_input(number_input_dialog, 3)

    def testDeleteOneUndefinedComp(self):
        init(complexStructure, pgmTestCat)

        len_ = model.getLength()
        num_components = model.get_num_components()

        set_selection([0])
        comp_len = model.getComponent(0).getLength()
        invoke(delete_action)
        self.assertEqual(len_, len_-comp_len)
        self.assertEqual(model.getNumSelectedComponentRows(), 1)
        self.assertEqual(model.getSelectedRows()[0], 0)

    def testDuplicateAction(self):
        init(complexStructure, pgmTestCat)

        run_swing_with_exception(lambda: model.set_component_name(1, "comp1"))
        len_ = model.getLength()
        num_components = model.get_num_components()

        # Duplicate Byte
        set_selection([1])
        dt_1 = get_data_type(1)
        dt_2 = get_data_type(2)

        invoke(duplicate_action)
        self.assertEqual(num_components, model.getNumComponents())
        self.assertEqual(len_, model.getLength())

    def testEditComponentAction(self):
        run_swing(lambda: install_provider(new StructureEditorProvider(plugin, complexStructure, False)))
        waitForSwing()
        get_actions()

        assertEquals("", model.getStatus())
        set_selection([21])  # 'simpleStructure'
        simple_sub_title = get_provider_subtitle(simpleStructure)
        self.assertTrue(is_provider_shown(tool.get_tool_frame(), "Structure Editor", complexSubTitle))

    def testFavoritesFixedOnMultiple(self):
        init(simpleStructure, pgmBbCat)

        dt = model.get_original_data_type_manager().get_data_type("/byte")
        assert dt is not None
        favorites_action = new FavoritesAction(provider, dt)
        num_components = model.getNumComponents()
        set_selection([3, 4, 5])  # 16 bytes selected

    def testApplyComponentChange(self):
        init(complexStructure, pgmTestCat)

        set_selection([3, 4])
        run_swing(lambda: try:
            model.clear_selected_components()
            model.delete_selected_components()
        except UsrException as e:
            fail_with_exception("Unexpected error", e))

    def testEditComponentAction_complex_structure(self):
        init(complexStructure, pgmTestCat)

        run_swing(lambda: install_provider(new StructureEditorProvider(plugin, complexStructure, False)))
        waitForSwing()
        get_actions()

        assertEquals("", model.getStatus())
        set_selection([20])  # 'simpleStructureTypedef * *[2][3]'
