Here is the translation of the given Java code into equivalent Python:

```Python
import unittest
from ghidra.app.merge.tree import ProgramTreeMergeManager, DummyMergeManager
from ghidra.program.model.listing import ProgramChangeSet
from ghidra.util.exception import CancelledException
from ghidra.util.task import TaskMonitorAdapter

class AbstractProgramTreeMergeManagerTest(unittest.TestCase):

    def setUp(self):
        self.main_tree_count = 0
        self.tree_three_count = 0

    def execute_merge(self, option=-1):
        original_program = mtf.get_original_program()
        my_program = mtf.get_private_program()
        result_program = mtf.get_result_program()
        latest_program = mtf.get_latest_program()

        result_change_set = mtf.get_result_change_set()
        my_change_set = mtf.get_private_change_set()

        dummy_merge_manager = DummyMergeManager(result_program, my_program, original_program, 
                                                  latest_program, result_change_set, my_change_set)
        program_tree_merge_manager = ProgramTreeMergeManager(dummy_merge_manager, result_program, 
                                                              my_program, original_program, 
                                                              latest_program, result_change_set, 
                                                              my_change_set)

        if option >= 0:
            program_tree_merge_manager.set_conflict_resolution(option)

        program_tree_merge_manager.merge(TaskMonitorAdapter.DUMMY_MONITOR)
        
    def merge(self):
        original_program = mtf.get_original_program()
        my_program = mtf.get_private_program()
        result_program = mtf.get_result_program()
        latest_program = mtf.get_latest_program()

        result_change_set = mtf.get_result_change_set()
        my_change_set = mtf.get_private_change_set()

        merge_mgr = ProgramMultiUserMergeManager(result_program, my_program, original_program, 
                                                  latest_program, result_change_set, my_change_set)
        
        t = threading.Thread(target=merge_mgr.merge)
        t.start()
        self.wait_for_swing()

    def press_apply(self):
        merge_plugin = mtf.get_instance_field("mergePlugin", merge_mgr)
        assert merge_plugin is not None
        provider = mtf.get_instance_field("provider", merge_plugin)
        assert provider is not None
        apply_button = mtf.get_instance_field("applyButton", provider)
        assert apply_button is not None
        self.press_button(apply_button)

    def resolve_name_conflicts_panel(self, info_string, option, use_for_all):
        self.wait_for_prompting()
        
        name_conflicts_panel = mtf.get_merge_panel(NameConflictsPanel)
        program_tree_merge_panel = mtf.get_merge_panel(ProgramTreeMergePanel)
        
        conflicts_label = mtf.get_instance_field("conflictsLabel", name_conflicts_panel)
        assert_equal(conflicts_label.text, info_string)

        if option == ProgramTreeMergeManager.KEEP_OTHER_NAME:
            latest_rb = mtf.get_instance_field("keepOtherRB", name_conflicts_panel)
            assert latest_rb is not None
            if not latest_rb.isSelected():
                self.press_button(latest_rb)
        
        elif option == ProgramTreeMergeManager.ADD_NEW_TREE:
            add_or_rename_rb = mtf.get_instance_field("addOrRenameRB", name_conflicts_panel)
            assert add_or_rename_rb is not None
            if not add_or_rename_rb.isSelected():
                self.press_button(add_or_rename_rb)

        elif option == ProgramTreeMergeManager.ORIGINAL_NAME:
            original_rb = mtf.get_instance_field("originalRB", name_conflicts_panel)
            assert original_rb is not None
            if not original_rb.isSelected():
                self.press_button(original_rb)

        else:
            raise ValueError(option + " is not a valid conflict option.")

        use_for_all_cb = mtf.get_instance_field("useForAllCB", program_tree_merge_panel)
        assert use_for_all_cb is not None
        use_for_all_cb.setSelected(use_for_all)

        self.wait_for_swing()
        
        self.wait_for_apply(True)
        self.press_button(apply_button)

    def resolve_name_panel(self, latest_name, my_name, option, use_for_all):
        self.wait_for_prompting()

        name_panel = mtf.get_merge_panel(NamePanel)
        program_tree_merge_panel = mtf.get_merge_panel(ProgramTreeMergePanel)
        
        tree_change_panel_one = mtf.get_instance_field("panelOne", program_tree_merge_panel)
        assert tree_change_panel_one is not None
        tree_name_label1 = mtf.get_instance_field("treeNameLabel", tree_change_panel_one)
        assert tree_name_label1 is not None

        tree_change_panel_two = mtf.get_instance_field("panelTwo", program_tree_merge_panel)
        assert tree_change_panel_two is not None
        tree_name_label2 = mtf.get_instance_field("treeNameLabel", tree_change_panel_two)
        assert tree_name_label2 is not None
        
        self.assertEqual(tree_name_label1.text, latest_name)
        self.assertEqual(tree_name_label2.text, my_name)

        if option == ProgramTreeMergeManager.KEEP_OTHER_NAME:
            latest_rb = mtf.get_instance_field("keepOtherRB", name_panel)
            assert latest_rb is not None
            if not latest_rb.isSelected():
                self.press_button(latest_rb)

        elif option == ProgramTreeMergeManager.KEEP_PRIVATE_NAME:
            my_rb = mtf.get_instance_field("keepMyRB", name_panel)
            assert my_rb is not None
            if not my_rb.isSelected():
                self.press_button(my_rb)

        elif option == ProgramTreeMergeManager.ADD_NEW_TREE:
            new_tree_rb = mtf.get_instance_field("newTreeRB", name_panel)
            assert new_tree_rb is not None
            new_tree_rb.setSelected(False)
            if not new_tree_rb.isSelected():
                self.press_button(new_tree_rb)

        elif option == ProgramTreeMergeManager.ORIGINAL_NAME:
            original_rb = mtf.get_instance_field("originalRB", name_panel)
            assert original_rb is not None
            if not original_rb.isSelected():
                self.press_button(original_rb)

        else:
            raise ValueError(option + " is not a valid conflict option.")

        use_for_all_cb = mtf.get_instance_field("useForAllCB", program_tree_merge_panel)
        assert use_for_all_cb is not None
        use_for_all_cb.setSelected(use_for_all)

        self.wait_for_swing()
        
        self.wait_for_apply(True)
        self.press_button(apply_button)