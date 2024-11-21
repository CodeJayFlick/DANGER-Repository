import unittest
from ghidra.program.model.data import *
from docking.widgets.dialogs.numberinputdialog import NumberInputDialog
from time import sleep

class StructureEditorUnlockedDnD3Test(unittest.TestCase):

    def setUp(self):
        super().setUp()
        self.env.show_tool()

    def init(self, dt, cat):
        super().init(dt, cat, False)
        run_swing(lambda: None)  # equivalent to model.setLocked(False)

    @unittest.skip("Not implemented yet")
    def test_drag_and_drop_insert_different_types(self):

        dialog = None
        self.init(empty_structure, pgm_root_cat)
        dt = program_dtm.get_data_type("/byte")

        assert_equal(0, model.num_components())
        assert_equal(0, model.length)

        insert_at_point(dt, 0, 0)
        assert_equal(1, model.num_components())
        assert_true(get_data_type(0).is_equivalent(dt))
        assert_equal(dt.length(), model.component(0).length)
        assert_equal(1, model.length)

        dt = program_dtm.get_data_type("/double")
        insert_at_point(dt, 0, 0)
        assert_equal(2, model.num_components())
        assert_true(get_data_type(0).is_equivalent(dt))
        assert_equal(dt.length(), model.component(0).length)
        assert_equal(9, model.length)

        dt3 = program_dtm.get_data_type("/undefined *32")
        insert_at_point(dt3, 1, 0)
        assert_equal(3, model.num_components())
        assert_true(get_data_type(1).is_equivalent(dt3))
        assert_equal(4, model.component(1).length)
        assert_equal(13, model.length)

        dt4 = program_dtm.get_data_type("/string")
        insert_at_point(dt4, 0, 0)
        dialog = self.env.wait_for_dialog_component(NumberInputDialog, 1000)
        ok_input(dialog, 25)
        sleep(2)  # equivalent to wait_until_dialog_provider_gone
        assert_equal(4, model.num_components())
        assert_true(get_data_type(0).is_equivalent(dt4))
        assert_equal(25, model.component(0).length)
        assert_equal(38, model.length)

if __name__ == '__main__':
    unittest.main()
