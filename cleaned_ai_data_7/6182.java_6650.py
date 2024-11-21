import unittest
from threading import Thread
from time import sleep
from tkinter as tk
from tkinter.messagebox import showinfo

class AbstractDataTypeMergeTest(unittest.TestCase):

    def setUp(self):
        self.data_type_merge_mgr = None
        self.test_monitor = TaskMonitorAdapter()
        self.window = None

    def execute_merge(self, do_wait=False):
        original_program = mtf.get_original_program()
        my_program = mtf.get_private_program()
        result_program = mtf.get_result_program()
        latest_program = mtf.get_latest_program()

        result_change_set = mtf.get_result_change_set()
        my_change_set = mtf.get_private_change_set()

        merge_mgr = create_merge_manager(result_change_set, my_change_set)

        self.test_monitor.clear_canceled()
        started = CountDownLatch(1)
        done = CountDownLatch(1)
        t = Thread(target=lambda: (
            try:
                started.count_down()
                merge_mgr.merge(self.test_monitor)
                done.count_down()
            except CancelledException as e:
                # can't happen
                pass))
        t.start()

        self.assertTrue("Merge never started", started.await(timeout=DEFAULT_WAIT_TIMEOUT, unit='milliseconds'))
        sleep(1)  # wait for swing

        self.window = get_merge_window(done)

        if do_wait:
            t.join()
        else:
            showinfo('Info', 'Test completed')

    def execute_dummy_merge(self):
        original_program = mtf.get_original_program()
        my_program = mtf.get_private_program()
        result_program = mtf.get_result_program()
        latest_program = mtf.get_latest_program()

        merge_mgr = DummyMergeManager(result_program, my_program, original_program, latest_program)
        data_type_merge_mgr = DataTypeMergeManager(merge_mgr, result_program, my_program, original_program, latest_program)

        t = Thread(target=lambda: (
            try:
                merge_mgr.merge()
            except CancelledException as e:
                # User cancelled.
                pass))
        t.start()

        sleep(1)  # wait for swing

    def resolve_category_conflict(self, option, use_for_all=False):
        self.waitForPrompting()

        category_merge_panel = get_merge_panel(CategoryMergePanel)
        conflict_panel = get_merge_panel(CategoryConflictPanel)

        assert isinstance(category_merge_panel, CategoryMergePanel), 'category merge panel is not of the expected type'
        assert isinstance(conflict_panel, CategoryConflictPanel), 'conflict panel is not of the expected type'

    def resolve_conflict(self, option, use_for_all=False):
        self.waitForPrompting()

        if option == DataTypeMergeManager.OPTION_LATEST:
            latest_rb = getInstanceField("latestRB", conflict_panel)
            assert isinstance(latest_rb, JRadioButton), 'radio button is not of the expected type'
            if not latest_rb.isSelected():
                pressButton(latest_rb)

        elif option == DataTypeMergeManager.OPTION_MY:
            my_rb = getInstanceField("myRB", conflict_panel)
            assert isinstance(my_rb, JRadioButton), 'radio button is not of the expected type'
            if not my_rb.isSelected():
                pressButton(my_rb)

        elif option == DataTypeMergeManager.OPTION_ORIGINAL:
            orig_rb = getInstanceField("originalRB", conflict_panel)
            assert isinstance(orig_rb, JRadioButton), 'radio button is not of the expected type'
            if not orig_rb.isSelected():
                pressButton(orig_rb)

    def check_conflict_count(self, expected_count):
        data_type_manager = result_program.get_data_type_manager()
        list = []
        data_type_manager.find_data_types("*.conflict*", list, False, None)
        self.assertEqual(expected_count, len(list))

if __name__ == '__main__':
    unittest.main()
