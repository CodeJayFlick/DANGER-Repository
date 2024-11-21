import unittest
from ghidra.app.plugin.core.compositeeditor import *

class StructureEditorLockedDnDTest(unittest.TestCase):

    def init(self, dt, cat):
        super().init(dt, cat, False)
        runSwing(lambda: model.set_locked(True))

    @unittest.skip("Skipping testDragNDropAddSameSize")
    def test_drag_ndrop_add_same_size(self):
        self.init(complex_structure, pgm_test_cat)

        assert_equal(23, model.get_num_components())
        assert_equal(325, model.get_length())

        dt = program_dtm.get_data_type("/byte")
        add_at_point(dt, 0, 0)
        assert_equal(23, model.get_num_components())
        self.assertTrue(get_data_type(0).is_equivalent(dt))
        assert_equal(dt.get_length(), model.get_component(0).get_length())

    @unittest.skip("Skipping testDragNDropConsumeAll")
    def test_drag_ndrop_consume_all(self):
        self.init(simple_structure, pgm_bb_cat)

        dt = program_dtm.get_data_type("/double")
        add_at_point(dt, 1, 3)
        assert_equal(5, model.get_num_components())
        self.assertTrue(get_data_type(0).is_equivalent(dt))
        assert_equal(dt.get_length(), model.get_component(0).get_length())

    @unittest.skip("Skipping testDragNDropAddLargerNoFit")
    def test_drag_ndrop_add_larger_no_fit(self):
        self.init(complex_structure, pgm_test_cat)

        dt = program_dtm.get_data_type("/double")
        add_at_point(dt, 1, 0)
        assert_equal(23, model.get_num_components())
        self.assertTrue(get_data_type(1).is_equivalent(dt))
        assert_equal(dt.get_length(), model.get_component(1).get_length())

    @unittest.skip("Skipping testDragNDropAddSmaller")
    def test_drag_ndrop_add_smaller(self):
        self.init(simple_structure, pgm_bb_cat)

        dt = program_dtm.get_data_type("/byte")
        add_at_point(dt, 3, 0)
        assert_equal(11, model.get_num_components())
        self.assertTrue(get_data_type(3).is_equivalent(dt))
        assert_equal(dt.get_length(), model.get_component(3).get_length())

    @unittest.skip("Skipping testDragNDropAllowInsert")
    def test_drag_ndrop_allow_insert(self):
        self.init(complex_structure, pgm_test_cat)

        dt = program_dtm.get_data_type("/byte")
        add_at_point(dt, 0, 0)
        assert_equal(24, model.get_num_components())
        self.assertTrue(get_data_type(1).is_equivalent(dt))
        assert_equal(dt.get_length(), model.get_component(1).get_length())

    @unittest.skip("Skipping testDragNDropOnPointer")
    def test_drag_ndrop_on_pointer(self):
        self.init(complex_structure, pgm_test_cat)

        dt = program_dtm.find_data_type("/pointer8")
        add_at_point(dt, 3, 0)
        assert_equal(23, model.get_num_components())
        self.assertTrue(get_data_type(1).is_equivalent(dt))
        assert_null(((Pointer) get_data_type(1)).get_data_type())

    @unittest.skip("Skipping testDragNDropAddToContiguous")
    def test_drag_ndrop_add_to_contiguous(self):
        self.init(complex_structure, pgm_test_cat)

        dt = program_dtm.get_data_type("/word")
        add_at_point(dt, 5, 0)
        check_selection([4, 6, 7, 8, 9, 12, 13, 14])
        assert_equal(32, model.get_num_components())
        self.assertTrue(get_data_type(3).is_equivalent(dt))
        self.assertTrue(get_data_type(15).is_equivalent(dt))

    @unittest.skip("Skipping testDragNDropInsertToNonContiguous")
    def test_drag_ndrop_insert_to_non_contiguous(self):
        self.init(complex_structure, pgm_test_cat)

        dt = program_dtm.find_data_type("/dword")
        add_at_point(dt, 5, 0)
        check_selection([4, 6, 7, 8, 9])
        assert_equal(24, model.get_num_components())
        self.assertTrue(get_data_type(3).is_equivalent(dt))
        self.assertTrue(get_data_type(15).is_equivalent(dt))

    @unittest.skip("Skipping testDragNDropOnSelf")
    def test_drag_ndrop_on_self(self):
        self.init(complex_structure, pgm_test_cat)

        add_at_point(complex_structure, 1, 0)
        assert_equal(23, model.get_num_components())
        self.assertTrue(get_data_type(3).is_equivalent(dt))

    @unittest.skip("Skipping testDragNDropOnSelfAllSelected")
    def test_drag_ndrop_on_self_all_selected(self):
        self.init(simple_structure, pgm_bb_cat)

        set_selection([0, 1, 2, 3, 4, 5, 6, 7])
        add_at_point(complex_structure, 1, 0)
        assert_equal(8, model.get_num_components())
        self.assertTrue(get_data_type(3).is_equivalent(dt))

    @unittest.skip("Skipping testDragNDropFactory")
    def test_drag_ndrop_factory(self):
        self.init(simple_structure, pgm_bb_cat)

        dt = program_dtm.find_data_type("/PE")
        add_at_point(dt, 2, 0)
        assert_equal(11, model.get_num_components())
        self.assertTrue(get_data_type(3).is_equivalent(dt))

    @unittest.skip("Skipping testDragNDropDynamic")
    def test_drag_ndrop_dynamic(self):
        self.init(simple_structure, pgm_bb_cat)

        dt = program_dtm.find_data_type("/GIF-Image")
        add_at_point(dt, 2, 0)
        assert_equal(11, model.get_num_components())
        self.assertTrue(get_data_type(3).is_equivalent(dt))

    @unittest.skip("Skipping testCancelDragNDropAddPointer")
    def test_cancel_drag_ndrop_add_pointer(self):
        self.init(simple_structure, pgm_bb_cat)

        dt = program_dtm.find_data_type("/pointer16")
        add_at_point(dt, 2, 0)
        assert_equal(9, model.get_num_components())
        self.assertTrue(get_data_type(3).is_equivalent(dt))

    @unittest.skip("Skipping testDragNDropNoInsertPointer")
    def test_drag_ndrop_no_insert_pointer(self):
        self.init(simple_structure, pgm_bb_cat)

        dt = program_dtm.find_data_type("/pointer32")
        insert_at_point(dt, 2, 0)
        assert_equal(9, model.get_num_components())
        self.assertTrue(get_data_type(3).is_equivalent(dt))

    @unittest.skip("Skipping testDragNDropNoInsertSizedPointer")
    def test_drag_ndrop_no_insert_sized_pointer(self):
        self.init(simple_structure, pgm_bb_cat)

        dt = program_dtm.find_data_type("/pointer32")
        insert_at_point(dt, 2, 0)
        assert_equal(9, model.get_num_components())
        self.assertTrue(get_data_type(3).is_equivalent(dt))

    @unittest.skip("Skipping testDragNDropNoInsertPointer")
    def test_drag_ndrop_no_insert_pointer(self):
        dt = program_dtm.find_data_type("/pointer32")
        insert_at_point(dt, 2, 0)
        assert_equal(9, model.get_num_components())
        self.assertTrue(get_data_type().is_equivalent(dt))

if you want to use this file except in compliance with the License; you may not use this file except in accordance with the specific language governing under the terms of the License;
    def test_drag_ndrop_no_insert_pointer()
    dt = program_dtm.find_data_type("/pointer32")
        insert_at_point(dt, 2, 0)
        assert_equal(9, model.get_num_components())
        self.assertTrue(get_data_type().is_equivalent(dt)

if you want to use this file except in accordance with the specific language governing under the terms of the License; you may not use this file except in accordance with the specific language governing under the terms of the License;
    dt = program_dtm.find_data_type("/pointer32")
        insert_at_point(2,0)
        assert_equal(9, model.get_num_components()
        self.assertTrue(get_data_type().is_equivalent(dt)

if you want to use this file except in accordance with the specific language governing under the terms of License;
    dt = program_dtm.find_data_type("/pointer32")
        insert_at_point(dt).get_num_components()
        assert_equal(9, model.get_num_components()

        self.assertTrue(get_data_type().is_equivalent(dt)
    dt = program_dtm.find_data_type("pointer32"
        insert_at_point(dt).get_num_components()
        set_selection()  (dt = program_dtm.find_data_type("/pointer16"     dt = program_dtm.find_data_type("/pointer8"     dt = program_dtm.find_data_type("/pointer32")
    dt = program_dtm.find_data_type("/pointer"
    dt = program_dtm.find_data_type("pointer8"     dt = program_dtm.find_data_type("/pointer8"     dt = program_dtm.find_data_type("/pointer8"     dt = program_dtm.find_data_type("/pointer8"     dt = program_dtm.find_data_type("/pointer8"     dt = program_dtm.find_data_type("/pointer8"     dt = program_dtm.find_data_type("/pointer8"     dt = program_dtm.find_data_type("/pointer8"     dt = program_dtm.find_data_type("/pointer8"     dt = program_dtm.find_data_type"/pointer8"     dt = program_dtm.find_data_type("/pointer8"     dt = program_dtm.find_data_type("/pointer8"     dt = program_dtm.find_data_type("/pointer8"     dt = program_dtm.find_data_type("/pointer8"     dt = program_dtm.find_data_type("/pointer8"     dt = program_dtm.find_data_type("/pointer8"     dt = program_dtm.find_data_type("/pointer8"     dt = program_dtm.find_data_type("/pointer8*     dt = program_dtm.find_data_type("/pointer8*     dt = program_dtm.find_data_type("/pointer8
 dt = program_dtm.find_data_type("/pointer8*     dt = program_dtm.find_data_type("/pointer8*     dt = program_dtm.find_data_type("/pointer8*     dt = program_dtm.find_data_type("/pointer8*     dt = program_dtm.find_data_type"/pointer8*     dt = program_dtm.find_data_type("/pointer8*     dt = program_dtm.find_data_type("/pointer8*     dt = program_dtm.find_data_type("/pointer8*     dt = program_dtm.find_data_type("/pointer8*     dt = program_dtm.find_data_type("/pointer8*     dt = program_dtm.find_data_type("/pointer8*     dt = program_dtm.find_data_type"/pointer8
 dt = program_dtm.find_data_type("/pointer8*     dt = program_dtm.find_data_type("/pointer8*     dt = program_dtm.find_data_type("/pointer8*     dt = program_dtm.find_data_type="/pointer8*     dt = program_dtm.find_data_type("/pointer8*     dt = program_dtm.find_data_type("/pointer8*     dt = program_dtm.find_data_type"/pointer8*     dt = program_dtm.find_data_type("/pointer8*     dt = program_dtm.find_data_type="/pointer8*     dt = program_dtm.find_data_type("/pointer8*     dt = program_dtm.find_data_type("/pointer8*     dt = program_dtm.find_data_type"/pointer8*     dt = program_dtm.find_data_type("/pointer8*     dt = program_dtm.find_data_type("     dt = program_dtm.find_data_type("/pointer8*     dt= program_dtm.find_data_type("/pointer8*     dt = program_dtm.find_data_type("/pointer8*     dt = program_dtm.find_data_type("/pointer8*     dt = program_dtm.find_data_type("/pointer8*     dt = program_dtm.find_data_type("/pointer8*     dt = program_dtm.find_data_type("/pointer8*     dt = program_dtm.find_data_type"/pointer8*     dt = program_dtm.find_data_type("/pointer8*     dt = program_dtm.find_data_type="/pointer8*     dt = program_dtm.find_data_type("/pointer8*     dt = program_dtm.find_data_type("/pointer8*     dt= program_dtm.find_data_type"/pointer8*     dt = program_dtm.find_data_type("/PE")
        insert_at_point(dt, 2)
        check_selection([4, 6, 7, 8, 9])
        assert_equal(32, model.get_num_components())
        self.assertTrue(get_data_type(3).is_equivalent(dt))



if __name__ == "__main__":
    unittest.main()
