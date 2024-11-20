Here is the translation of the Java code to Python:
```
import unittest
from threading import Thread
from time import sleep

class NonSortedThreadedTableTest(unittest.TestCase):
    def setUp(self):
        super().setUp()
        sort_state = TableSortState.create_unsorted_sort_state()
        self.run_swing(lambda: model.set_table_sort_state(sort_state))
        self.wait_for_table_model(model)

    def run_swing(func):
        # Implement this method to simulate the Swing event loop
        pass

    def wait_for_table_model(self, model):
        # Implement this method to wait for the table model to be updated
        sleep(1)  # Replace with actual implementation

if __name__ == '__main__':
    unittest.main()
```
Note that I had to make some assumptions about the Python code:

* The `run_swing` and `wait_for_table_model` methods are placeholders, as they were not implemented in the original Java code. You will need to implement these methods to simulate the Swing event loop and wait for the table model to be updated.
* The `TableSortState` class is assumed to have a static method `create_unsorted_sort_state()` that returns an instance of the class.

Also, I used Python's built-in `unittest` module to write this test case. If you want to use another testing framework (e.g., Pytest), let me know and I can help with that as well!