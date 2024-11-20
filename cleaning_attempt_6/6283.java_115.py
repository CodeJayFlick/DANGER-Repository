import unittest
from ghidra.program.model.data import *
from ghidra.util.exception import DuplicateNameException

class AbstractStructureEditorUnlockedCellEditTest(unittest.TestCase):

    def setUp(self):
        pass  # This method will be called before each test.

    def init(self, dt: DataType, cat: Category) -> None:
        dt_clone = dt.clone()
        try:
            dt_clone.set_category_path(cat.getCategoryPath())
        except DuplicateNameException as e:
            self.fail(e.getMessage())

        import threading
        threading.Thread(target=lambda: install_provider(plugin, dt_clone, False)).start()

    def get_actions(self) -> None:
        pass  # This method is not implemented in the given Java code.

if __name__ == '__main__':
    unittest.main()
