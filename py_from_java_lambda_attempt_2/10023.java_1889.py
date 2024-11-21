Here's your Java code translated into Python:

```Python
import unittest
from threading import Thread
from time import sleep

class AbstractThreadedTableTest(unittest.TestCase):

    def setUp(self):
        self.model = self.create_test_model()
        self.test_table_model_listener = self.create_listener()
        self.model.add_threaded_table_model_listener(self.test_table_model_listener)

        # do this in swing, as some of the table column setup can trigger concurrent modifications
        # due to the swing and the test working on the widgets at the same time
        def run_swing(func):
            Thread(target=func).start()
            while True:
                if not self.is_disposing():
                    break
                sleep(0.1)

        run_swing(lambda: 
            self.threaded_table_panel = GThreadedTablePanel(self.model)
            self.table = self.threaded_table_panel.get_table()
            self.header = self.table.get_header()

            build_frame(self.threaded_table_panel)
        )

    def create_test_model(self):
        # This method should be implemented in the subclass
        pass

    def create_listener(self):
        return TestThreadedTableModelListener(self.model)

    def tearDown(self):
        self.is_disposing = True
        self.dispose()

    def dispose(self):
        close(self.frame)
        run_swing(lambda: 
            if hasattr(self.threaded_table_panel, 'dispose'):
                self.threaded_table_panel.dispose()
        )

    def add_item_to_model(self, value):
        self.model.add_object(Long(value))
        self.wait_for_table_model(self.model)

    def remove_item_from_model(self, value):
        self.model.remove_object(Long(value))
        self.wait_for_table_model(self.model)

    def trigger_model_filter(self):
        self.model.re_filter()
        self.wait_for_table_model(self.model)

    def do_test_sorting(self, column_index):
        self.sort_by_normal_clicking(column_index)
        
        sorted_model = SortedTableModel(self.table.get_model())
        self.verify_sort_direction(column_index, sorted_model)

        self.sort_by_normal_clicking(column_index)
        self.verify_sort_direction(column_index, sorted_model)

    def verify_sort_direction(self, column_index, sorted_model):
        sort_state = get_sort_state(sorted_model)
        if not sort_state.is_unsorted():
            original_column_sort_state = next(iter(sort_state))
            current_sort_colunn = original_column_sort_state.get_column_model_index()
            check_sort_direction = (column_index == current_sort_colunn)

            for i in range(self.table.get_row_count() - 1):
                comp1 = self.table.get_value_at(i + 0, column_index)
                comp2 = self.table.get_value_at(i + 1, column_index)

                if original_column_sort_state.is_ascending():
                    compare_result = compare_values(comp1, comp2)
                    less_than_or_equal_to = (compare_result <= 0)
                    self.assertTrue(f'"{comp1}" is not <= "{comp2}"', less_than_or_equal_to)
                else:
                    compare_result = compare_values(comp1, comp2)
                    greater_than_or_equal_to = (compare_result >= 0)
                    self.assertTrue(f'"{comp1}" is not >= "{comp2}"', greater_than_or_equal_to)

    def sort_by_normal_clicking(self, column_index):
        self.sort_by_click(column_index, 0)

    def sort_by_click(self, column_index, modifiers):
        sorted_model = SortedTableModel(self.table.get_model())
        test_table_model_listener.reset(self.model)
        
        rect = self.header.get_header_rect(column_index)
        if not self.header.is_showing():
            sleep(50)
            while True:
                if not self.is_disposing():
                    break
                sleep(0.1)

        record(f'Clicking table at column {column_index}')
        click_mouse(self.header, MouseEvent.BUTTON1, rect.x + 10, rect.y + 10, 1, modifiers)
        
        sorted_state = get_sort_state(sorted_model)
        self.verify_column_sorted(column_index, sorted_state)

    def remove_sort_by_clicking(self, column_to_click):
        sorted_model = SortedTableModel(self.table.get_model())

        test_table_model_listener.reset(self.model)
        rect = self.header.get_header_rect(column_to_click)
        
        click_mouse(self.header, MouseEvent.BUTTON1, rect.x + 10, rect.y + 10, 1,
            DockingUtils.CONTROL_KEY_MODIFIER_MASK)

        sorted_state = get_sort_state(sorted_model)
        assert not any((sort_state for sort_state in sorted_state if column_to_click == sort_state.get_column_model_index()))

    def verify_column_sorted(self, sorted_index, table_sort_state):
        column_sort_state = next(iter(table_sort_state))
        self.assertIsNotNone(column_sort_state)

    def reset_busy_listener(self):
        test_table_model_listener.reset(self.model)

    def wait_for_not_busy(self):
        sleep(50)
        while True:
            if not self.is_disposing():
                break
            sleep(0.1)
        self.wait_for_swing()

    def add_long(self, value):
        run_swing(lambda: 
            self.model.add_object(Long(value))
        )

    def get_row_count(self):
        return run_swing(lambda: 
            self.model.get_row_count()
        )

    def get_unfiltered_row_count(self):
        return run_swing(lambda: 
            self.model.get_unfiltered_row_count()
        )

    def get_model_data(self):
        return run_swing(lambda: 
            self.model.get_model_data()
        )
```

Please note that Python does not have direct equivalent of Java's Swing, so some parts might be different.