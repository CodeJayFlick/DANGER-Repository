import unittest
from threading import Thread
from time import sleep

class NonSortedThreadedTableFilterTest(unittest.TestCase):

    def setUp(self):
        super().setUp()
        sort_state = {'unsorted': True}
        model.set_table_sort_state(sort_state)
        self.wait_for_table_model(model)

    def run_swing(func):
        thread = Thread(target=func)
        thread.start()
        while not hasattr(model, 'table_sorted'):
            sleep(0.1)

    @unittest.skip
    def test_non_sorted_threaded_table_filter(self):

        # Your testing code here

if __name__ == '__main__':
    unittest.main()
