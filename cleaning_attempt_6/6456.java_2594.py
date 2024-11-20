import unittest
from ghidra.app.plugin.core.stackeditor import StackEditorEnablementTest


class TestStackEditorEnablement(StackEditorEnablementTest):

    def test_empty_stack_editor_state(self):
        self.init(EMPTY_STACK)
        
        self.assertEqual(4, self.stack_model.get_num_components())
        self.assertEqual(4, self.stack_model.get_row_count())
        self.assertEqual(0, self.stack_model.get_length())
        self.assertTrue(not self.stack_model.has_changes())
        self.assertTrue(self.stack_model.is_valid_name())
        self.assertEqual(0, self.stack_model.get_num_selected_component_rows())
        self.assertEqual(0, self.stack_model.get_num_selected_rows())

        for action in self.actions:
            if isinstance(action, (CycleGroupAction, HexNumbersAction)):
                self.check_enablement(action, True)
            else:
                self.check_enablement(action, False)

    def test_no_var_neg_stack_editor_state(self):
        self.init(NO_VAR_NEG_STACK)
        
        self.assertEqual(4, self.stack_model.get_num_components())
        self.assertEqual(4, self.stack_model.get_row_count())
        self.assertEqual(0x1e, self.stack_model.get_length())
        self.assertTrue(not self.stack_model.has_changes())
        self.assertTrue(self.stack_model.is_valid_name())

        for action in self.actions:
            if isinstance(action, (CycleGroupAction, HexNumbersAction)):
                self.check_enablement(action, True)
            else:
                self.check_enablement(action, False)

    def test_simple_neg_stack_editor_state(self):
        self.init(SIMPLE_NEG_STACK)
        
        self.assertEqual(20, self.model.get_num_components())
        self.assertEqual(0x1e, self.model.get_length())

        for action in self.actions:
            if isinstance(action, (FavoritesAction)):
                fav = FavoritesAction()
                dt = fav.get_data_type()
                len_ = dt.get_length()
                enabled = (len_ <= num_bytes) and ((dt is Pointer) or (len_ > 0))
                self.check_enablement(action, enabled)
            elif isinstance(action, (CycleGroupAction, HexNumbersAction)):
                self.check_enablement(action, True)
            else:
                self.check_enablement(action, False)

    def test_first_component_selected_enablement(self):
        self.init(SIMPLE_NEG_STACK)
        
        run_swing(lambda: model.set_selection([0]))
        num_bytes = getModel().get_max_replace_length(0)
        for action in self.actions:
            if isinstance(action, (FavoritesAction)):
                fav = FavoritesAction()
                dt = fav.get_data_type()
                len_ = dt.get_length()
                enabled = (len_ <= num_bytes) and ((dt is Pointer) or (len_ > 0))
                self.check_enablement(action, enabled)
            elif isinstance(action, (CycleGroupAction, HexNumbersAction)):
                self.check_enablement(action, True)
            else:
                self.check_enablement(action, False)

    def test_central_component_selected_enablement(self):
        self.init(SIMPLE_NEG_STACK)
        
        run_swing(lambda: model.set_selection([1]))
        num_bytes = getModel().get_max_replace_length(1)
        for action in self.actions:
            if isinstance(action, (FavoritesAction)):
                fav = FavoritesAction()
                dt = fav.get_data_type()
                len_ = dt.get_length()
                enabled = (len_ <= num_bytes) and ((dt is Pointer) or (len_ > 0))
                self.check_enablement(action, enabled)
            elif isinstance(action, (CycleGroupAction, HexNumbersAction)):
                self.check_enablement(action, True)
            else:
                self.check_enablement(action, False)

    def test_last_component_selected_enablement(self):
        self.init(SIMPLE_NEG_STACK)
        
        run_swing(lambda: model.set_selection([model.get_num_components() - 1]))
        num_bytes = getModel().get_max_replace_length(model.get_num_components() - 1)
        for action in self.actions:
            if isinstance(action, (FavoritesAction)):
                fav = FavoritesAction()
                dt = fav.get_data_type()
                len_ = dt.get_length()
                enabled = (len_ <= num_bytes) and ((dt is Pointer) or (len_ > 0))
                self.check_enablement(action, enabled)
            elif isinstance(action, (CycleGroupAction, HexNumbersAction)):
                self.check_enablement(action, True)
            else:
                self.check_enablement(action, False)

    def test_contiguous_selection_enablement(self):
        self.init(SIMPLE_NEG_STACK)
        
        run_swing(lambda: model.set_selection([2, 3, 4]))
        for action in self.actions:
            if isinstance(action, (CycleGroupAction, HexNumbersAction)):
                self.check_enablement(action, True)
            else:
                self.check_enablement(action, False)

    def test_non_contiguous_selection_enablement(self):
        self.init(SIMPLE_NEG_STACK)
        
        run_swing(lambda: model.set_selection([2, 3, 6, 7]))
        for action in self.actions:
            if isinstance(action, (CycleGroupAction, HexNumbersAction)):
                self.check_enablement(action, True)
            else:
                self.check_enablement(action, False)


if __name__ == '__main__':
    unittest.main()
