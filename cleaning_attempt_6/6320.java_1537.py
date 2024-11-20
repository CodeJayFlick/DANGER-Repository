import unittest

class ZeroSizeStructureTest(unittest.TestCase):

    def testCreateEmptyStructure(self):
        init(empty_structure, pgm_root_cat, False)
        
        self.assertIsNone(pgm_root_cat.get_data_type(empty_structure.name))
        
        self.assertEqual(0, model.num_components)  # no components
        self.assertEqual(1, model.row_count)  # blank row
        self.assertEqual(0, model.length)  # size is 0
        self.assertTrue(model.has_changes())  # new empty structure
        self.assertTrue(model.is_valid_name())
        self.assertEqual(empty_structure.description, model.description)
        self.assertEqual(0, model.num_selected_component_rows)
        self.assertEqual(1, model.num_selected_rows)
        check_selection([0])
        assert_is_packing_enabled(False)  # no packing enabled
        assert_is_default_aligned()
        assert_actual_alignment(1)
        assert_length(0)
        self.assertEqual(empty_structure.name, model.composite_name)
        self.assertEqual(pgm_root_cat.category_path_name(), model.original_category_path.path)
        self.assertEqual("Structure", model.type_name)
        self.assertFalse(apply_action.is_enabled())
        assert_status("")
        
        invoke(apply_action)
        
        dt = pgm_root_cat.get_data_type(empty_structure.name)
        self.assertIsNotNone(dt)  # not null
        self.assertTrue(dt.is_not_yet_defined())  # is not yet defined
        self.assertTrue(dt.is_zero_length())  # zero length
        
        assert_is_packing_enabled(False)  # no packing enabled
        assert_is_default_aligned()
        assert_actual_alignment(1)
        assert_length(0)
        self.assertEqual(empty_structure.name, model.composite_name)
        self.assertEqual(pgm_root_cat.category_path_name(), model.original_category_path.path)
        self.assertEqual("Structure", model.type_name)
        self.assertFalse(apply_action.is_enabled())
        assert_status("")
    
    def testCanZeroDataTypeIfComponent(self):
        inner_structure_impl = StructureDataType("inner_structure", 0)  # component 0
        inner_structure_impl.add(DataType.DEFAULT)  # add default data type
        
        outer_structure_impl = new StructureDataType("outer_structure", 0)
        outer_structure_impl.add(inner_structure_impl)  # add structure as a component
        
        init(outer_structure_impl, pgm_test_cat, False)
        
        dt = pgm_test_cat.get_data_type(outer_structure_impl.name)
        self.assertIsNotNone(dt)  # not null
        self.assertFalse(dt.is_zero_length())  # is not zero length
        
        delete_all_components()
        
        assert_is_packing_enabled(False)  # no packing enabled
        assert_is_default_aligned()
        assert_actual_alignment(1)
        assert_length(0)
        self.assertEqual(outer_structure_impl.name, model.composite_name)
        self.assertEqual(pgm_test_cat.category_path_name(), model.original_category_path.path)
        self.assertEqual("Structure", model.type_name)
        self.assertTrue(apply_action.is_enabled())
        
        invoke(apply_action)
        
        dt = pgm_test_cat.get_data_type(inner_structure_impl.name)  # get data type
        self.assertIsNotNone(dt)  # not null
        self.assertTrue(dt.is_not_yet_defined())  # is not yet defined
        self.assertTrue(dt.is_zero_length())  # zero length
        
    def testCanZeroDataTypeIfPointerComponent(self):
        inner_structure_impl = new StructureDataType("inner_structure", 0)
        outer_structure_impl = new StructureDataType("outer_structure", 0)
        
        try:
            tx_id = program.start_transaction("Change DataType")
            
            inner_structure = program_dtm.resolve(inner_structure_impl, None)  # resolve structure
            outer_structure = program_dtm.resolve(outer_structure_impl, None)  # resolve structure
            
        finally:
            program.end_transaction(tx_id, True)
        
        assertNotNull(inner_structure)  # not null
        assertNotNull(outer_structure)  # not null
        
    def testCanZeroDataTypeIfNonPointerComponent(self):
        inner_structure_impl = new StructureDataType("inner_structure", 0)
        outer_structure_impl = new StructureDataType("outer_structure", 0)
        
        try:
            tx_id = program.start_transaction("Change DataType")
            
            inner_structure = program_dtm.resolve(inner_structure_impl, None)  # resolve structure
            outer_structure = program_dtm.resolve(outer_structure_impl, None)  # resolve structure
            
        finally:
            program.end_transaction(tx_id, True)
        
    def testCanZeroDataTypeIfInTypedef(self):
        inner_structure_impl = new StructureDataType("inner_structure", 0)
        typedef_impl = new TypedefDataType("typedef", inner_structure_impl)
        
        try:
            tx_id = program.start_transaction("Change DataType")
            
            inner_structure = program_dtm.resolve(inner_structure_impl, None)  # resolve structure
            typedef = program_dtm.resolve(typedef_impl, None)  # resolve typedef
            
        finally:
            program.end_transaction(tx_id, True)
        
    def testCanZeroDataTypeIfInArray(self):
        inner_structure_impl = new StructureDataType("inner_structure", 0)
        array_impl = new ArrayDataType(inner_structure_impl, 5, 2)
        
        try:
            tx_id = program.start_transaction("Change DataType")
            
            inner_structure = program_dtm.resolve(inner_structure_impl, None)  # resolve structure
            array = program_dtm.resolve(array_impl, None)  # resolve array
            
        finally:
            program.end_transaction(tx_id, True)

    def delete_all_components(self):
        while model.length > 0:  # no components
            model.set_selection([0])
            invoke(delete_action)
        
if __name__ == "__main__":
    unittest.main()
