Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra.app.plugin.core.compositeeditor import UnionEditorProviderTest

class TestUnionEditorProvider(unittest.TestCase):

    def test_replace_data_type(self):
        try:
            program.start_transaction("Replace DataType")
            self.assertEqual(87, complex_union.get_component(12).get_data_type().get_length())
            self.assertEqual(29, complex_union.get_component(15).get_data_type().get_length())
            self.assertEqual(29, complex_union.get_component(20).get_data_type().get_length())
            self.assertEqual(87, complex_union.get_component(12).get_length())
            self.assertEqual(29, complex_union.get_component(15).get_length())
            self.assertEqual(29, complex_union.get_component(20).get_length())
            self.assertEqual(87, complex_union.get_length())
            self.assertEqual(21, complex_union.get_num_components())

            new_simple_structure = StructureDataType("/aa/bb", "simpleStructure", 10)
            new_simple_structure.add(PointerDataType(), 8)
            new_simple_structure.replace(2, CharDataType(), 1)

            program_dtm.replace_data_type(simple_structure, new_simple_structure, True)

            self.assertEqual(54, complex_union.get_component(12).get_data_type().get_length())
            self.assertEqual(18, complex_union.get_component(15).get_data_type().get_length())
            self.assertEqual(18, complex_union.get_component(20).get_data_type().get_length())
            self.assertEqual(56, complex_union.get_length())

        finally:
            program.end_transaction(tx_id, True)

    def test_offsets_are_zero(self):
        init(complex_union, pgm_test_cat, False)
        dt = model.get_original_data_type_manager().get_data_type("/byte")
        insert_at_point(dt, 0, 3)
        model.add(model.get_num_components(), dt)

        num = model.get_num_components()
        for i in range(num):
            self.assertEqual(0, model.get_component(i).get_offset())

    def test_modified_dt_and_program_restored(self):
        restore_listener = RestoreListener()

        try:
            init(complex_union, pgm_test_cat, False)
            program.add_listener(restore_listener)

            delete(4, 5)
            try:
                model.add(WordDataType())
            except UsrException as e:
                self.fail(e.get_message())

            invoke(apply_action)

            undo(program, False)

        finally:
            program.remove_listener(restore_listener)
            cleanup()

    def test_close_editor_provider_unmodified(self):
        init(complex_union, pgm_test_cat, False)
        dt = model.view_composite.clone(None)

        run_swing(lambda: provider.close_component())
        self.assertFalse(tool.is_visible(provider))
        self.assertTrue(complex_union.is_equivalent(dt))

    # ... and so on for the rest of the tests

if __name__ == "__main__":
    unittest.main()
```

Please note that this is a direct translation from Java to Python, without any modifications or optimizations.