import unittest
from ghidra_tablechooser import TableChooserDialogTest
from ghidra_tablechooser import SpyTableChooserExecutor
from ghidra_tablechooser import TestStubRowObject
from ghidra_tablechooser import OffsetTestColumn
from ghidra_tablechooser import SpaceTestColumn

class TableChooserDialogTest(unittest.TestCase):

    def setUp(self):
        self.executor = SpyTableChooserExecutor()
        create_dialog(self.executor)

    def tearDown(self):
        run_swing(lambda: tool.close())

    def test_closed_listener(self):
        called = [False]
        dialog.set_closed_listener(lambda: called[0] = True)
        run_swing(lambda: dialog.close())
        self.assertTrue("Dialog 'closed' listener not called", called[0])

    # ... and so on for the rest of the tests

def create_dialog(dialog_executor):
    tool = DummyPluginTool()
    tool.setVisible(True)

    addresses = []
    toy_program_builder = ToyProgramBuilder("Test", True)
    builder.create_memory(".text", "0x0", 0x110)
    f = create_function(builder, 0x00)
    addresses.append(f.get_entry_point())
    # ... and so on for the rest of the functions

def re_create_dialog(dialog_executor):
    run_swing(lambda: dialog.close())
    create_dialog(dialog_executor)

# ... and so on for the other methods
