import unittest
from ghidra_program import *
from data_type_manager import DataTypeManager
from category_path import CategoryPath


class AbstractStructureEditorLockedActionsTest(unittest.TestCase):

    def setUp(self):
        self.commit = True
        self.start_transaction("Structure Editor Test Initialization")
        
    def test_init(self):
        dt = Structure()
        cat = Category()
        try:
            data_type_manager = cat.get_data_type_manager()
            if dt.get_data_type_manager() != data_type_manager:
                dt = dt.clone(data_type_manager)
            
            category_path = cat.get_category_path()
            if not dt.get_category_path().equals(category_path):
                try:
                    dt.set_category_path(category_path)
                except DuplicateNameException as e:
                    self.commit = False
                    self.fail(e.message)

        finally:
            end_transaction(self.commit)

    def test_install_provider(self):
        structure_dt = Structure()
        run_swing(lambda: install_provider(StructureEditorProvider(plugin, structure_dt, False)))
        model = provider.get_model()

    def test_wait_for_swing(self):
        wait_for_swing()

    def get_actions(self):
        pass
