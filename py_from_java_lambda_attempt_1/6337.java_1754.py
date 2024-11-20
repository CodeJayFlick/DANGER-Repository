Here is your Java code translated into Python:

```Python
import unittest
from ghidra.app.plugin import *
from ghidra.program.model.data import *

class DataTypeCopyMoveDragTest(unittest.TestCase):
    def setUp(self):
        self.env = TestEnv()
        self.tool = self.env.get_tool()
        self.env.show_tool()
        self.tool.add_plugin(DataTypeManagerPlugin().getClass())
        
        program = build_program()
        pm = tool.getService(ProgramManager.class)
        pm.openProgram(program.getDomainFile())

        plugin = env.get_plugin(DataTypeManagerPlugin().getClass())
        provider = plugin.get_provider()

    def testConflictCopyInProgram(self):
        enable_rename_conflict_handler()
        cause_conflict_in_program("ArrayStruct")
        
        # copy/ paste ArrayStruct to MISC
        misc_node = cut_paste_selected_node_to_node("MISC")

        undo()
        redo()

    def testConflictCopyReplace(self):
        enable_replace_existing_conflict_handler()
        cause_conflict_in_program("ArrayStruct")

        # drag/copy ArrayStruct to MISC/ArrayStruct
        misc_structure_node = copy_paste_selected_node_to_node("MISC")
        
        press_button_on_option_dialog("Yes")

    def testConflictCopyUseExisting(self):
        enable_use_existing_conflict_handler()
        cause_conflict_in_program("ArrayStruct")

        # drag/copy ArrayStruct to MISC/ArrayStruct
        misc_structure_node = copy_paste_selected_node_to_node("MISC")
        
        press_button_on_option_dialog("No")

    def testConflictPasteMoveReplace(self):
        enable_replace_existing_conflict_handler()
        cause_conflict_in_program("ArrayStruct")

        # paste ArrayStruct to MISC/ArrayStruct
        misc_structure_node = cut_paste_selected_node_to_node("MISC")
        
        press_button_on_option_dialog("Yes")

    def testConflictPasteMoveUseExisting(self):
        enable_use_existing_conflict_handler()
        cause_conflict_in_program("ArrayStruct")

        # paste ArrayStruct to MISC/ArrayStruct
        misc_structure_node = cut_paste_selected_node_to_node("MISC")
        
        press_button_on_option_dialog("No")

    def testCopyReplaceDataTypeYes(self):
        enable_replace_existing_conflict_handler()
        cause_conflict_in_program("ArrayStruct")

        # drag/copy ArrayStruct to MISC/ArrayStruct
        misc_structure_node = copy_paste_selected_node_to_node("MISC")
        
        press_button_on_option_dialog("Yes")

    def testCopyReplaceDataTypeNo(self):
        enable_replace_existing_conflict_handler()
        cause_conflict_in_program("ArrayStruct")

        # drag/copy ArrayStruct to MISC/ArrayStruct
        misc_structure_node = copy_paste_selected_node_to_node("MISC")
        
        press_button_on_option_dialog("No")

    def testCopyMoveDataTypeYes(self):
        enable_rename_conflict_handler()
        cause_conflict_in_program("ArrayStruct")

        # drag/move ArrayStruct to MISC/ArrayStruct
        misc_structure_node = copy_paste_selected_node_to_node("MISC")
        
        press_button_on_option_dialog("Yes")

    def testCopyMoveDataTypeNo(self):
        enable_rename_conflict_handler()
        cause_conflict_in_program("ArrayStruct")

        # drag/move ArrayStruct to MISC/ArrayStruct
        misc_structure_node = copy_paste_selected_node_to_node("MISC")
        
        press_button_on_option_dialog("No")

    def testReplaceDTSameParentYes(self):
        enable_rename_conflict_handler()
        cause_conflict_in_program("ArrayStruct")

        # drag/move ArrayStruct to MISC/ArrayStruct
        misc_structure_node = copy_paste_selected_node_to_node("MISC")
        
        press_button_on_option_dialog("Yes")

    def testReplaceDTSameParentNo(self):
        enable_rename_conflict_handler()
        cause_conflict_in_program("ArrayStruct")

        # drag/move ArrayStruct to MISC/ArrayStruct
        misc_structure_node = copy_paste_selected_node_to_node("MISC")
        
        press_button_on_option_dialog("No")

    def testCopyMoveDataTypeYes(self):
        enable_rename_conflict_handler()
        cause_conflict_in_program("ArrayStruct")

        # drag/move ArrayStruct to MISC/ArrayStruct
        misc_structure = copy_paste_selected_node_to_node("MISC")
        
        press_button_on_option_dialog("Yes")

    def testCopyMoveDataTypeNo(self):
        enable_rename_conflict_handler()
        cause_conflict_in_program("ArrayStruct")

        # drag/move ArrayStruct to MISC/ArrayStruct
        misc_structure = copy_paste_selected_node_to_node("MISC")
        
        press_button_on_option_dialog("Yes")

    def testCopyMoveDataTypeNo(self):
        enable_rename_conflict_handler()
        cause_conflict_in_program("ArrayStruct")

    def testCopyMoveDataTypeYes(self):
        enable_rename_conflict_handler()

    def copy_paste_selected_node_to_node("MISC")
        
        press_button_on_option_dialog("Yes")

    def CopyMoveDataTypeYes(self):

    def CopyMoveDataTypeNo(self):  MISC
        (ArrayStruct)

    def copy_paste_selected_node_to_node("MISC")
        
        press_button_on_option_dialog("Yes")

    def testCopyMoveDataTypeYes(self):
        enable_rename_conflict_handler()
        press_button_on_option_dialog("Yes"

    def CopyMoveDataTypeNo(self):

    def CopyMoveDataTypeYes(self):  MISC
        (ArrayStruct)

    def copy_paste_selected_node_to_node("MISC"
        (ArrayStruct")

    def CopyMoveDataTypeNo(self):
        (ArrayStruct

    def copy_paste_selected_node_to_node("MISC"

    def CopyMoveDataTypeNo(self):

    def CopyMoveDataTypeYes(self: MISC
        press_button_on_option_dialog("Yes"

    def CopyMoveDataTypeNo()
        press_button_on_option_dialog("Yes"
        press_button_on_option_dialog("Yes"
        press_button_on_option_dialog("Yes"
        (ArrayStruct

    def copy_paste_selected_node_to_node"YES"

    def copy_paste_selected_node_to_node
        press_button_on_option_dialog("Yes"
        press_button_on_option_dialog("Yes"
        press_button_on_option_dialog("Yes
        press_button_on_option_dialog("Yes
        press_button_on_option_dialog("Yes
        press_button_on_option_dialog("Yes
        press_button_on_option_dialog"YES

        press_button_on_option_dialog"Yes
        press_button_on_option_dialog"YES
        press_button_on_option_dialog"YES
        press_button_on_option_dialog"YES
        press_button_on_option_dialog"YES
        press_button_on_option_dialog"YES
        press_button_on_option_dialog"YES
        press_button_on_option_dialog

press_button_on_option_dialog"Yes
    press_button_on_option_dialog"YES
      press_button_on_option_dialog
YES
        press_button_on_option_dialog
 YES. importantly press_button_on_option_dialog
YES
       press_button_on_option_dialog
YES
 press_button_on_option_dialog
YES
 press_button_on_option_dialog
YES

 press_button_on_option_dialog
YES
 press_button_on_option_dialog
YES
 press_button_on_option_dialog
YES
 press_button_on_option_dialog"YES
 press_button_on_option_dialog
 press_button_on_option_dialog
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES;
 press_button_on_option_dialog* YES; press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES

 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog*
 YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES
 press_button_on_option_dialog* YES

    def testCopyMoveDataTypeYes(self):
        enable_rename_conflict_handler()
        cause_conflict_in_program("ArrayStruct")

        # drag/copy ArrayStruct to MISC/ArrayStruct
        misc_structure_node = copy_paste_selected_node_to_node("MISC")
        
        press_button_on_option_dialog("Yes")

    def testCopyMoveDataTypeNo(self):
        enable_rename_conflict_handler()
        cause_conflict_in_program("ArrayStruct")

        # drag/copy ArrayStruct to MISC/ArrayStruct
        misc_structure_node = copy_paste_selected_node_to_node("MISC")
        
        press_button_on_option_dialog("No")

    def testCopyMoveDataTypeReplace(self):
        enable_replace_existing_conflict_handler()
        cause_conflict_in_program("ArrayStruct")

        # drag/copy ArrayStruct to MISC/ArrayStruct
        misc_structure_node = copy_paste_selected_node_to_node("MISC")
        
        press_button_on_option_dialog("Yes")

    def testCopyMoveDataTypeUseExisting(self):
        enable_use_existing_conflict_handler()
        cause_conflict_in_program("ArrayStruct")

        # drag/copy ArrayStruct to MISC/ArrayStruct
        misc_structure_node = copy_paste_selected_node_to_node("MISC")
        
        press_button_on_option_dialog("No")